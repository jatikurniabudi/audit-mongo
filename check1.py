import subprocess

def check_1_1(required_major=7):
    section = "1.1 Ensure the appropriate MongoDB software version/patches are installed"

    try:
        # Ambil versi MongoDB dari output perintah `mongod --version`
        output = subprocess.check_output(['mongod', '--version']).decode()
        version_line = output.splitlines()[0]  # Misalnya: "db version v7.0.5"
        version = version_line.split()[-1].lstrip('v')  # Hapus 'v' jika ada

        # Pisahkan dan ambil versi major
        major_version = int(version.split('.')[0])

        if major_version >= required_major:
            status = True
            reason = f"MongoDB version is {version}, which meets the minimum required version {required_major}."
            recommendation = "No action needed. Ensure you keep the patch version up to date."
        else:
            status = False
            reason = f"MongoDB version is {version}, which is below the required major version {required_major}."
            recommendation = f"Upgrade MongoDB to version {required_major}.x or later."

    except Exception as e:
        status = False
        reason = f"Failed to determine MongoDB version: {str(e)}"
        recommendation = "Ensure MongoDB is installed and 'mongod' command is available in PATH."

    # Output hasil audit
    print(f"[{'OK' if status else 'FAIL'}] {section}")
    print(f"    Reason        : {reason}")
    print(f"    Recommendation: {recommendation}\\n")


if __name__ == '__main__':
    check_1_1()
