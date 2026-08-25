#include <crow.h>
#include <curl/curl.h>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
#include <sodium.h>

#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <map>
#include <optional>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "tas_types.hpp"

#ifdef TAS_ENABLE_SEAL
#include "fhe_store.hpp"
#endif

TasKeyInfo load_or_create_keys(const std::string & root);
void create_session_layout(const std::string & root,
  const std::string & session_id,
    const nlohmann::json & meta);

// from src/crypto.cpp
std::vector < unsigned char > decrypt_sealed_box(
  const std::vector < unsigned char > & cipher,
    const std::vector < unsigned char > & pk,
      const std::vector < unsigned char > & sk);

// Helpers

static std::string make_uuid_like() {
  static
  const char * chars = "0123456789abcdef";
  static thread_local std::mt19937 rng(std::random_device {}());
  std::uniform_int_distribution < int > d(0, 15);
  std::string out(36, '0');
  for (int i = 0; i < 36; ++i) {
    if (i == 8 || i == 13 || i == 18 || i == 23) out[i] = '-';
    else out[i] = chars[d(rng)];
  }
  return out;
}

static std::vector < unsigned char > b64_to_bytes(const std::string & b64) {
  // Allocate upper bound
  std::vector < unsigned char > out(b64.size());
  size_t out_len = 0;

  if (sodium_base642bin(
      out.data(),
      out.size(),
      b64.c_str(),
      b64.size(),
      /*ignore=*/
      nullptr, &
      out_len,
      /*b64_end=*/
      nullptr,
      sodium_base64_VARIANT_ORIGINAL) != 0) {
    throw std::runtime_error("invalid_base64");
  }

  out.resize(out_len);
  return out;
}

static std::vector < double > parse_vector_from_decrypted(const std::vector < unsigned char > & plain) {
  // Expect plaintext to be UTF-8 JSON array: [1.0, 2.0, ...]
  const std::string s(reinterpret_cast <
    const char * > (plain.data()), plain.size());
  auto j = nlohmann::json::parse(s);

  if (!j.is_array()) throw std::runtime_error("plaintext_not_array");

  std::vector < double > v;
  v.reserve(j.size());
  for (const auto & x: j) {
    if (!x.is_number()) throw std::runtime_error("plaintext_array_not_numeric");
    v.push_back(x.get < double > ());
  }
  return v;
}

static std::optional < crow::response > enforce_orchestrator_ip(
  const crow::request & req,
    const std::string & allowed_ip_env) {
  // If not set, allow all (local dev).
  if (allowed_ip_env.empty()) return std::nullopt;

  const std::string remote_ip = req.remote_ip_address;
  if (remote_ip != allowed_ip_env) {
    return crow::response(
      403,
      nlohmann::json {
        {
          "detail",
          "forbidden"
        }, {
          "reason",
          "ip_not_allowed"
        }, {
          "remote_ip",
          remote_ip
        }
      }
      .dump());
  }

  return std::nullopt;
}

static int env_to_int(const char * name, int default_value) {
  const char * v = std::getenv(name);
  if (!v) return default_value;
  try {
    return std::stoi(v);
  } catch (...) {
    return default_value;
  }
}

static size_t curl_write_cb(void * contents, size_t size, size_t nmemb, void * userp) {
  const size_t total = size * nmemb;
  auto * out = static_cast < std::vector < unsigned char > * > (userp);
  auto * ptr = static_cast < unsigned char * > (contents);
  out -> insert(out -> end(), ptr, ptr + total);
  return total;
}

static std::vector < unsigned char > fetch_url_bytes(const std::string & url) {
  CURL * curl = curl_easy_init();
  if (!curl) throw std::runtime_error("curl_init_failed");

  std::vector < unsigned char > out;
  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, & out);

  const CURLcode rc = curl_easy_perform(curl);
  long status = 0;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, & status);
  curl_easy_cleanup(curl);

  if (rc != CURLE_OK) throw std::runtime_error("curl_request_failed");
  if (status < 200 || status >= 300) throw std::runtime_error("curl_http_status_non_2xx");

  return out;
}

static bool try_build_aggregate(
  const std::string & data_dir,
    const std::string & session_id,
      const TasKeyInfo & key_info,
        std::string & error_out) {
  try {
    const auto base = std::filesystem::path(data_dir) / "sessions" / session_id;
    const auto inputs_dir = base / "inputs";
    const auto aggregate_dir = base / "aggregate";
    const auto output_path = aggregate_dir / "aggregated.safetensors";
    const auto weights_path = aggregate_dir / "weights.json";

    std::filesystem::create_directories(aggregate_dir);

    std::map < std::string, double > weights;
    size_t count = 0;

    if (!std::filesystem::exists(inputs_dir)) {
      error_out = "inputs_dir_missing";
      return false;
    }

    for (const auto & entry: std::filesystem::directory_iterator(inputs_dir)) {
      if (!entry.is_regular_file()) continue;
      const auto p = entry.path();
      if (p.extension() != ".json" || p.filename().string().find(".meta") == std::string::npos) {
        continue;
      }

      std::ifstream in (p);
      nlohmann::json meta;
      in >> meta;

      std::string sid = meta.value("submission_id", "");
      if (sid.empty()) sid = p.filename().string();
      const std::string suffix = ".meta.json";
      if (sid.size() >= suffix.size() && sid.compare(sid.size() - suffix.size(), suffix.size(), suffix) == 0) {
        sid = sid.substr(0, sid.size() - suffix.size());
      }

      double weight = 1.0;
      if (meta.contains("weight") && meta["weight"].is_number()) {
        weight = meta["weight"].get < double > ();
      } else if (
        meta.contains("meta") && meta["meta"].is_object() &&
        meta["meta"].contains("num_samples") && meta["meta"]["num_samples"].is_number()) {
        weight = meta["meta"]["num_samples"].get < double > ();
      }

      std::vector < unsigned char > payload;

      if (meta.contains("ciphertext_b64") && meta["ciphertext_b64"].is_string()) {
        auto ct = b64_to_bytes(meta["ciphertext_b64"].get < std::string > ());
        payload = decrypt_sealed_box(ct, key_info.public_key, key_info.secret_key);
      } else {
        std::string url = meta.value("ciphertext_download_url", "");
        if (url.empty()) url = meta.value("ciphertext_uri", "");

        // Backward-compatible fallbacks
        if (url.empty()) url = meta.value("url", "");
        if (url.empty()) url = meta.value("update_url", "");
        if (url.empty()) url = meta.value("update_uri", "");

        if (url.rfind("http://", 0) == 0 || url.rfind("https://", 0) == 0) {
          payload = fetch_url_bytes(url);

          if (meta.value("encrypted", false)) {
            payload = decrypt_sealed_box(payload, key_info.public_key, key_info.secret_key);
          }
        }
      }

      if (payload.empty()) {
        error_out = "empty_payload_for_submission";
        return false;
      }

      std::ofstream out(inputs_dir / (sid + ".safetensors"), std::ios::binary);
      out.write(reinterpret_cast <
        const char * > (payload.data()), static_cast < std::streamsize > (payload.size()));

      weights[sid] = weight;
      ++count;
    }

    if (count == 0) {
      error_out = "no_inputs";
      return false;
    }

    std::ofstream w(weights_path);
    w << nlohmann::json(weights).dump();
    w.flush();
    w.close();

    std::vector < std::filesystem::path > helper_candidates = {
      std::filesystem::current_path() / "tas_helper" / "aggregate.py",
      std::filesystem::current_path() / "tas" / "tas_helper" / "aggregate.py",
    };

    std::filesystem::path helper_path;
    for (const auto & candidate: helper_candidates) {
      if (std::filesystem::exists(candidate)) {
        helper_path = candidate;
        break;
      }
    }
    if (helper_path.empty()) {
      error_out = "aggregate_helper_not_found";
      return false;
    }

    std::ostringstream cmd;
    cmd << "python3 " << helper_path.string() << " --inputs " << inputs_dir.string() << " --weights " <<
      weights_path.string() << " --output " << output_path.string();

    const int rc = std::system(cmd.str().c_str());
    if (rc != 0 || !std::filesystem::exists(output_path)) {
      error_out = "aggregate_helper_failed";
      return false;
    }
    return true;
  } catch (const std::exception & e) {
    error_out = e.what();
    return false;
  }
}

// Server

void run_http_server() {
  const std::string data_dir =
    std::getenv("TAS_DATA_DIR") ? std::getenv("TAS_DATA_DIR") : "/var/lib/tas";

  const std::string allowed_orch_ip =
    std::getenv("TAS_ALLOWED_ORCH_IP") ? std::getenv("TAS_ALLOWED_ORCH_IP") : "";

  const int port = env_to_int("TAS_PORT", 9000);

  auto key_info = load_or_create_keys(data_dir);
  #ifdef TAS_ENABLE_SEAL
  auto fhe_key_info = load_or_create_fhe_keys(data_dir);
  #endif

  crow::SimpleApp app;

  // Public endpoints

  CROW_ROUTE(app, "/v1/health").methods(crow::HTTPMethod::Get)([] {
    return crow::response {
      nlohmann::json {
        {
          "status",
          "ok"
        }
      }.dump()
    };
  });

  CROW_ROUTE(app, "/v1/key-info").methods(crow::HTTPMethod::Get)([ & key_info] {
    nlohmann::json j {
      {
        "key_id",
        key_info.key_id
      }, {
        "public_key_b64",
        key_info.public_key_b64
      }, {
        "public_key_hash",
        key_info.public_key_hash
      }, {
        "created_at",
        key_info.created_at
      }, {
        "algorithm",
        "x25519_sealed_box_v1"
      }
    };
    return crow::response {
      j.dump()
    };
  });

  #ifdef TAS_ENABLE_SEAL
  CROW_ROUTE(app, "/v1/fhe/key-info").methods(crow::HTTPMethod::Get)([ & fhe_key_info] {
    nlohmann::json j {
      {
        "scheme",
        fhe_key_info.scheme
      }, {
        "algorithm",
        fhe_key_info.algorithm
      }, {
        "key_hash",
        fhe_key_info.key_hash
      }, {
        "created_at",
        fhe_key_info.created_at
      }, {
        "params",
        {
          {
            "poly_modulus_degree",
            fhe_key_info.poly_modulus_degree
          },
          {
            "coeff_modulus_bits",
            fhe_key_info.coeff_modulus_bits
          },
          {
            "scale_bits",
            fhe_key_info.scale_bits
          }
        }
      }, {
        "blobs",
        {
          {
            "public_key",
            {
              {
                "sha256",
                fhe_key_info.public_key_blob.sha256
              },
              {
                "size",
                fhe_key_info.public_key_blob.size
              }
            }
          },
          {
            "relin_keys",
            {
              {
                "sha256",
                fhe_key_info.relin_keys_blob.sha256
              },
              {
                "size",
                fhe_key_info.relin_keys_blob.size
              }
            }
          },
          {
            "galois_keys",
            {
              {
                "sha256",
                fhe_key_info.galois_keys_blob.sha256
              },
              {
                "size",
                fhe_key_info.galois_keys_blob.size
              }
            }
          },
          {
            "params",
            {
              {
                "sha256",
                fhe_key_info.params_blob.sha256
              },
              {
                "size",
                fhe_key_info.params_blob.size
              }
            }
          }
        }
      }
    };

    crow::response r;
    r.code = 200;
    r.set_header("Content-Type", "application/json; charset=utf-8");
    r.body = j.dump();
    return r;
  });

  CROW_ROUTE(app, "/v1/fhe/blobs/<string>").methods(crow::HTTPMethod::Get)(
    [ & ](const std::string & name) {
      const std::string dir = data_dir + "/fhe_keys";

      std::string path;
      std::string sha;

      if (name == "public_key") {
        path = dir + "/public_key.bin";
        sha = fhe_key_info.public_key_blob.sha256;
      } else if (name == "relin_keys") {
        path = dir + "/relin_keys.bin";
        sha = fhe_key_info.relin_keys_blob.sha256;
      } else if (name == "galois_keys") {
        path = dir + "/galois_keys.bin";
        sha = fhe_key_info.galois_keys_blob.sha256;
      } else if (name == "params") {
        path = dir + "/params.bin";
        sha = fhe_key_info.params_blob.sha256;
      } else {
        crow::response r(404);
        r.set_header("Content-Type", "application/json; charset=utf-8");
        r.body = nlohmann::json {
          {
            "detail",
            "unknown_blob"
          }
        }.dump();
        return r;
      }

      std::ifstream f(path, std::ios::binary);
      if (!f) {
        crow::response r(404);
        r.set_header("Content-Type", "application/json; charset=utf-8");
        r.body = nlohmann::json {
          {
            "detail",
            "blob_not_found"
          }
        }.dump();
        return r;
      }

      std::string bytes((std::istreambuf_iterator < char > (f)), std::istreambuf_iterator < char > ());

      crow::response r;
      r.code = 200;
      r.set_header("Content-Type", "application/octet-stream");
      r.set_header("X-FHE-Blob-Name", name);
      r.set_header("X-FHE-Blob-Sha256", sha);
      r.body = std::move(bytes);
      return r;
    });

  // POST /v1/fhe/decrypt  (restricted by TAS_ALLOWED_ORCH_IP)
  CROW_ROUTE(app, "/v1/fhe/decrypt").methods(crow::HTTPMethod::Post)(
    [ & ](const crow::request & req) {
      // enforce IP restriction (same policy as orchestrator endpoints)
      if (auto denied = enforce_orchestrator_ip(req, allowed_orch_ip)) {
        return std::move( * denied);
      }

      try {
        auto body = nlohmann::json::parse(req.body);

        const std::string key_hash = body.value("key_hash", std::string {});
        if (key_hash.empty()) {
          crow::response r(400);
          r.set_header("Content-Type", "application/json; charset=utf-8");
          r.body = nlohmann::json {
            {
              "detail",
              "missing_key_hash"
            }
          }.dump();
          return r;
        }

        if (key_hash != fhe_key_info.key_hash) {
          crow::response r(409);
          r.set_header("Content-Type", "application/json; charset=utf-8");
          r.body = nlohmann::json {
            {
              "detail",
              "key_hash_mismatch"
            }, {
              "expected",
              fhe_key_info.key_hash
            }, {
              "got",
              key_hash
            }
          }.dump();
          return r;
        }

        if (!body.contains("ciphertext_b64") || !body["ciphertext_b64"].is_string()) {
          crow::response r(400);
          r.set_header("Content-Type", "application/json; charset=utf-8");
          r.body = nlohmann::json {
            {
              "detail",
              "missing_ciphertext_b64"
            }
          }.dump();
          return r;
        }

        const auto ct_b64 = body["ciphertext_b64"].get < std::string > ();
        auto ct_bytes = b64_to_bytes(ct_b64);

        const int expected_len = body.value("expected_vector_len", 0);

        auto vec = decrypt_ckks_ciphertext(fhe_key_info, ct_bytes);

        if (expected_len > 0) {
          if (static_cast<int>(vec.size()) < expected_len) {
            crow::response r(409);
            r.set_header("Content-Type", "application/json; charset=utf-8");
            r.body = nlohmann::json {
              {
                "detail",
                "vector_len_mismatch"
              }, {
                "expected",
                expected_len
              }, {
                "actual",
                vec.size()
              }
            }.dump();
            return r;
          }
          if (static_cast<int>(vec.size()) > expected_len) {
            vec.resize(static_cast<std::size_t>(expected_len));
          }
        }

        nlohmann::json out {
          {
            "key_hash",
            fhe_key_info.key_hash
          }, {
            "plaintext_vector",
            vec
          }
        };

        crow::response r;
        r.code = 200;
        r.set_header("Content-Type", "application/json; charset=utf-8");
        r.body = out.dump();
        return r;

      } catch (const nlohmann::json::parse_error & ) {
        crow::response r(400);
        r.set_header("Content-Type", "application/json; charset=utf-8");
        r.body = nlohmann::json {
          {
            "detail",
            "invalid_json"
          }
        }.dump();
        return r;
      } catch (const std::exception & ex) {
        crow::response r(400);
        r.set_header("Content-Type", "application/json; charset=utf-8");
        r.body = nlohmann::json {
          {
            "detail",
            "invalid_request"
          }, {
            "error",
            ex.what()
          }
        }.dump();
        return r;
      }
    });

  #endif

  CROW_ROUTE(app, "/docs").methods(crow::HTTPMethod::Get)([] {
    std::ifstream f("spec/swagger.html", std::ios::binary);
    if (!f) return crow::response(404);

    std::stringstream ss;
    ss << f.rdbuf();

    crow::response r;
    r.code = 200;
    r.set_header("Content-Type", "text/html; charset=utf-8");
    r.body = ss.str();
    return r;
  });

  CROW_ROUTE(app, "/v1/public-key").methods(crow::HTTPMethod::Get)([ & key_info] {
    crow::response r;
    r.code = 200;
    r.set_header("Content-Type", "application/octet-stream");
    r.body.assign(reinterpret_cast <
      const char * > (key_info.public_key.data()), key_info.public_key.size());
    return r;
  });

  // Serve OpenAPI YAML if present
  CROW_ROUTE(app, "/spec/openapi.yaml").methods(crow::HTTPMethod::Get)([] {
    std::ifstream f("spec/openapi.yaml", std::ios::binary);
    if (!f) return crow::response(404);

    std::stringstream ss;
    ss << f.rdbuf();

    crow::response r;
    r.code = 200;
    r.set_header("Content-Type", "application/yaml");
    r.body = ss.str();
    return r;
  });

  // Public session summary. TODO check if we will require auth.
  CROW_ROUTE(app, "/v1/sessions/<string>/summary").methods(crow::HTTPMethod::Get)(
    [ & ](const std::string & id) {
      const auto base = data_dir + "/sessions/" + id;
      nlohmann::json out {
        {
          "tas_session_id",
          id
        }, {
          "status",
          "OPEN"
        }, {
          "received",
          0
        }, {
          "buffer_target",
          0
        }, {
          "contributions",
          nlohmann::json::array()
        }
      };

      if (std::filesystem::exists(base + "/aggregate/aggregated.safetensors")) {
        out["status"] = "FINALIZED";
      }
      return crow::response {
        out.dump()
      };
    });

  // ---------- Public test endpoint ----------
  // POST /v1/test-aggregate
  // Body:
  // {
  //   "op": "sum" | "mean",
  //   "ciphertexts": ["base64(sealed_box(json_array))", ...],
  //   "max_dim": 200000   // optional
  // }
  CROW_ROUTE(app, "/v1/test-aggregate").methods(crow::HTTPMethod::Post)(
    [ & ](const crow::request & req) {
      try {
        auto body = nlohmann::json::parse(req.body);

        const std::string op = body.value("op", "sum");
        if (op != "sum" && op != "mean") {
          return crow::response(400, nlohmann::json {
            {
              "detail",
              "invalid_op"
            }
          }.dump());
        }

        if (!body.contains("ciphertexts") || !body["ciphertexts"].is_array()) {
          return crow::response(400, nlohmann::json {
            {
              "detail",
              "missing_ciphertexts"
            }
          }.dump());
        }

        const size_t max_dim = body.value("max_dim", 200000UL);
        const auto & arr = body["ciphertexts"];
        if (arr.empty()) {
          return crow::response(400, nlohmann::json {
            {
              "detail",
              "empty_ciphertexts"
            }
          }.dump());
        }

        std::vector < double > acc;
        size_t count = 0;

        for (const auto & item: arr) {
          if (!item.is_string()) {
            return crow::response(400, nlohmann::json {
              {
                "detail",
                "ciphertext_not_string"
              }
            }.dump());
          }

          const std::string ct_b64 = item.get < std::string > ();
          auto ct = b64_to_bytes(ct_b64);

          auto plain = decrypt_sealed_box(ct, key_info.public_key, key_info.secret_key);
          auto vec = parse_vector_from_decrypted(plain);

          if (vec.size() > max_dim) {
            return crow::response(400, nlohmann::json {
              {
                "detail",
                "dim_too_large"
              }
            }.dump());
          }

          if (count == 0) {
            acc = std::move(vec);
          } else {
            if (vec.size() != acc.size()) {
              return crow::response(400, nlohmann::json {
                {
                  "detail",
                  "dim_mismatch"
                }
              }.dump());
            }
            for (size_t i = 0; i < acc.size(); ++i) acc[i] += vec[i];
          }

          ++count;
        }

        if (op == "mean") {
          for (auto & x: acc) x /= static_cast < double > (count);
        }

        nlohmann::json out {
          {
            "op",
            op
          }, {
            "count",
            count
          }, {
            "dim",
            acc.size()
          }, {
            "result",
            acc
          }
        };
        return crow::response {
          out.dump()
        };

      } catch (const nlohmann::json::parse_error & ) {
        return crow::response(400, nlohmann::json {
          {
            "detail",
            "invalid_json"
          }
        }.dump());
      } catch (const std::exception & e) {
        return crow::response(
          400,
          nlohmann::json {
            {
              "detail",
              "test_aggregate_failed"
            }, {
              "error",
              e.what()
            }
          }.dump());
      }
    });

  // Restricted POST endpoints

  CROW_ROUTE(app, "/v1/sessions").methods(crow::HTTPMethod::Post)(
    [ & ](const crow::request & req) {
      if (auto deny = enforce_orchestrator_ip(req, allowed_orch_ip)) return std::move( * deny);

      try {
        auto body = nlohmann::json::parse(req.body);

        std::string session_id = make_uuid_like();
        create_session_layout(data_dir, session_id, body);

        nlohmann::json out {
          {
            "tas_session_id",
            session_id
          }, {
            "key_hash",
            key_info.public_key_hash
          }, {
            "created_at",
            "startup"
          }
        };

        return crow::response {
          out.dump()
        };
      } catch (const nlohmann::json::parse_error & ) {
        return crow::response(400, nlohmann::json {
          {
            "detail",
            "invalid_json"
          }
        }.dump());
      } catch (const std::exception & e) {
        return crow::response(500, nlohmann::json {
          {
            "detail",
            "create_session_failed"
          }, {
            "error",
            e.what()
          }
        }.dump());
      }
    });

  CROW_ROUTE(app, "/v1/sessions/<string>/inputs").methods(crow::HTTPMethod::Post)(
    [ & ](const crow::request & req,
      const std::string & id) {
      if (auto deny = enforce_orchestrator_ip(req, allowed_orch_ip)) return std::move( * deny);

      try {
        auto body = nlohmann::json::parse(req.body);

        if (!body.contains("submission_id") || !body["submission_id"].is_string()) {
          return crow::response(400, nlohmann::json {
            {
              "detail",
              "missing_submission_id"
            }
          }.dump());
        }

        const auto submission_id = body["submission_id"].get < std::string > ();
        const auto base = data_dir + "/sessions/" + id;

        std::filesystem::create_directories(base + "/inputs");

        std::ofstream(base + "/inputs/" + submission_id + ".meta.json") << body.dump(2);

        // NOTE: we may need to increment buffer stats in sessions.cpp later
        return crow::response {
          nlohmann::json {
            {
              "ok",
              true
            }, {
              "received",
              1
            }, {
              "buffer_target",
              1
            }
          }.dump()
        };
      } catch (const nlohmann::json::parse_error & ) {
        return crow::response(400, nlohmann::json {
          {
            "detail",
            "invalid_json"
          }
        }.dump());
      } catch (const std::exception & e) {
        return crow::response(500, nlohmann::json {
          {
            "detail",
            "submit_input_failed"
          }, {
            "error",
            e.what()
          }
        }.dump());
      }
    });

  CROW_ROUTE(app, "/v1/sessions/<string>/finalize").methods(crow::HTTPMethod::Post)(
    [ & ](const crow::request & req,
      const std::string & id) {
      if (auto deny = enforce_orchestrator_ip(req, allowed_orch_ip)) return std::move( * deny);

      const auto output_path = data_dir + "/sessions/" + id + "/aggregate/aggregated.safetensors";
      if (!std::filesystem::exists(output_path)) {
        std::string aggregate_error;
        try_build_aggregate(data_dir, id, key_info, aggregate_error);
      }
      if (!std::filesystem::exists(output_path)) {
        // =========================
        // FIX #2: return proper JSON content-type on 409
        // =========================
        crow::response r;
        r.code = 409;
        r.set_header("Content-Type", "application/json; charset=utf-8");
        r.body = nlohmann::json {
          {
            "detail",
            "buffer_not_met"
          }, {
            "reason",
            "aggregate_missing"
          }, {
            "received",
            0
          }, {
            "target",
            1
          },
        }.dump();
        return r;
      }

      std::ifstream in (output_path, std::ios::binary);
      std::string bytes((std::istreambuf_iterator < char > (in)), std::istreambuf_iterator < char > ());

      crow::response out;
      out.code = 200;
      out.set_header("Content-Type", "application/octet-stream");
      out.set_header("X-TAS-Aggregate-Sha256", "");
      out.set_header("X-TAS-Num-Contributions", "0");
      out.body = bytes;
      return out;
    });

  // Thread cap and run
  app.concurrency(4);
  app.port(static_cast < uint16_t > (port)).run();
}