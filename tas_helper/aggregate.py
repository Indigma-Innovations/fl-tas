import argparse
import json
from pathlib import Path

import torch
from safetensors.torch import load_file, save_file


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inputs", required=True)
    parser.add_argument("--weights", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    text = Path(args.weights).read_text().strip()
    if not text:
        raise RuntimeError(f"weights.json empty: {args.weights}")
    weights = json.loads(text)
    input_dir = Path(args.inputs)
    updates = []
    for sid, weight in weights.items():
        tensors = load_file(str(input_dir / f"{sid}.safetensors"))
        updates.append((tensors, float(weight)))

    if not updates:
        raise RuntimeError("no updates")

    total_weight = sum(w for _, w in updates)
    agg = {}
    for key in updates[0][0].keys():
        base = None
        for tensors, weight in updates:
            t = tensors[key].to(torch.float32)
            base = t * weight if base is None else base + t * weight
        agg[key] = (base / total_weight).to(updates[0][0][key].dtype)

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    save_file(agg, str(args.output))


if __name__ == "__main__":
    main()
