from pathlib import Path

from demo_data import generate_demo_threat_files


def main() -> None:
    target = Path("data/demo_infected_samples")
    generated = generate_demo_threat_files(str(target), amount=25)
    print(f"Generated {len(generated)} harmless demo threat file(s) at {target.resolve()}")


if __name__ == "__main__":
    main()
