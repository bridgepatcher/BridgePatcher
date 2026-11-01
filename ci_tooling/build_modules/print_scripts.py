import package_scripts
import rich


def main():
    scripts = package_scripts.GenerateScripts()
    functions = {
        "preinstall_pkg.txt": scripts.preinstall_pkg,
        "preinstall_autopkg.txt": scripts.preinstall_autopkg,
        "postinstall_pkg.txt": scripts.postinstall_pkg,
        "postinstall_autopkg.txt": scripts.postinstall_autopkg,
        "uninstall.txt": scripts.uninstall,
    }
    # Generate and save each script
    for filename, func in functions.items():
        with open(filename, "w", encoding="utf-8") as f:
            f.write(func())
        rich.print(f"Saved {filename}")

if __name__ == "__main__":
    main()