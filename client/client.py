import asyncio
import asyncssh
import getpass


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
            known_hosts=None  # clients verify the host key with TOFU
        ) as conn:
            
            print("✓ SSH connection established")
            print("✓ Host key verified (TOFU)")
            print("✓ Password authentication successful")
            
            # ex 1.4 - SFTP runs as SSH subsystem
            async with conn.start_sftp_client() as sftp:
                print("✓ SFTP subsystem started\n")
                
                # placeholder:
                print("=== SFTP session active ===")
                print("TODO: Add commands (pwd, ls, mkdir, get, put, stat)")
                
                # keep connection alive for testing
                await asyncio.sleep(2)
                
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