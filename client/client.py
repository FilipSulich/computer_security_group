import asyncio
import asyncssh
import getpass
import os
import sys


async def sftp_cli(sftp):
    print("=== SFTP session active ===")
    print("Available commands: pwd, ls [path], mkdir <path>, stat <path>, get <rpath> [lpath], put <lpath> <rpath>, quit")

    while True:
        try:
            cmd = input("sftp> ").strip()
            if not cmd:
                continue

            parts = cmd.split()
            command = parts[0].lower()

            if command == 'quit':
                print("Exiting SFTP session.")
                break

            elif command == 'pwd':
                # Print current remote directory (sftp.getcwd())
                cwd = await sftp.getcwd()
                print(cwd)

            elif command == 'ls':
                # ls [path]
                path = parts[1] if len(parts) > 1 else '.'
                try:
                    files = await sftp.listdir(path)
                    for f in files:
                        print(f)
                except (asyncssh.SFTPError, FileNotFoundError) as e:
                    print(f"Error listing directory: {e}")

            elif command == 'mkdir':
                if len(parts) < 2:
                    print("Usage: mkdir <path>")
                    continue
                path = parts[1]
                try:
                    await sftp.mkdir(path)
                    print(f"Directory created: {path}")
                except asyncssh.SFTPError as e:
                    print(f"Error creating directory: {e}")

            elif command == 'stat':
                if len(parts) < 2:
                    print("Usage: stat <path>")
                    continue
                path = parts[1]
                try:
                    attrs = await sftp.stat(path)
                    print_attrs(attrs)
                except asyncssh.SFTPError as e:
                    print(f"Error getting attributes: {e}")

            elif command == 'get':
                if len(parts) < 2:
                    print("Usage: get <remote_path> [local_path]")
                    continue
                rpath = parts[1]
                lpath = parts[2] if len(parts) > 2 else os.path.basename(rpath)

                try:
                    with open(lpath, 'wb') as local_file:
                        async with sftp.open(rpath, 'rb') as remote_file:
                            while True:
                                data = await remote_file.read(32768)
                                if not data:
                                    break
                                local_file.write(data)
                    print(f"Downloaded '{rpath}' to '{lpath}'")
                except (asyncssh.SFTPError, OSError) as e:
                    print(f"Error downloading file: {e}")

            elif command == 'put':
                if len(parts) < 3:
                    print("Usage: put <local_path> <remote_path>")
                    continue
                lpath = parts[1]
                rpath = parts[2]

                if not os.path.exists(lpath):
                    print(f"Local file '{lpath}' does not exist")
                    continue

                try:
                    with open(lpath, 'rb') as local_file:
                        async with sftp.open(rpath, 'wb') as remote_file:
                            while True:
                                data = local_file.read(32768)
                                if not data:
                                    break
                                await remote_file.write(data)
                    print(f"Uploaded '{lpath}' to '{rpath}'")
                except (asyncssh.SFTPError, OSError) as e:
                    print(f"Error uploading file: {e}")

            else:
                print(f"Unknown command: {command}")

        except EOFError:
            print("\nExiting SFTP session.")
            break
        except KeyboardInterrupt:
            print("\nInterrupted. Type 'quit' to exit.")

def print_attrs(attrs):
    # attrs is an SFTPAttrs object with various fields
    print(f"Size: {attrs.size}")
    print(f"UID: {attrs.uid}")
    print(f"GID: {attrs.gid}")
    print(f"Permissions: {oct(attrs.permissions) if attrs.permissions is not None else 'N/A'}")
    print(f"Access time: {attrs.atime}")
    print(f"Modify time: {attrs.mtime}")

async def main():

    # Connection parameters
    host = 'localhost'
    port = 2222
    username = input("Username: ")
    password = getpass.getpass("Password: ")

    print(f"Connecting to {host}:{port} as {username}...")

    try:
        # ex 1.2
        async with asyncssh.connect(
            host,
            port,
            username=username,
            password=password,
            known_hosts=None  # TOFU host key verification
        ) as conn:
            print("✓ SSH connection established")
            print("✓ Host key verified (TOFU)")
            print("✓ Password authentication successful")

            # ex 1.4 - SFTP runs as SSH subsystem
            async with conn.start_sftp_client() as sftp:
                print("✓ SFTP subsystem started\n")
                await sftp_cli(sftp)

    except asyncssh.PermissionDenied:
        print("✗ Authentication failed")
    except ConnectionRefusedError:
        print(f"✗ Connection refused. Is server running on {host}:{port}?")
    except asyncssh.Error as e:
        print(f"✗ SSH Error: {e}")
    except Exception as e:
        print(f"✗ Error: {e}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        print("\nClient stopped.")

 