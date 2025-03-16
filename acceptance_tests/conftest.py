import os
import pytest
import subprocess
import time
import signal
from pathlib import Path

@pytest.fixture(scope="session")
def dns_server():
    """Start the DNS server for the duration of the test session."""
    # Get the path to the DNS server executable
    root_dir = Path(__file__).parent.parent
    server_path = root_dir / "cpp" / "build" / "dns_server"
    
    # Ensure the server is built
    if not os.path.exists(server_path):
        build_dir = root_dir / "cpp" / "build"
        if not os.path.exists(build_dir):
            os.makedirs(build_dir)
        
        subprocess.run(["cmake", ".."], cwd=build_dir, check=True)
        subprocess.run(["make"], cwd=build_dir, check=True)
    
    # Start the server
    server_process = subprocess.Popen([server_path], 
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE)
    
    # Wait a moment for the server to start
    time.sleep(1)
    
    # Check if the server started successfully
    if server_process.poll() is not None:
        stdout, stderr = server_process.communicate()
        pytest.fail(f"DNS server failed to start: {stderr.decode()}")
    
    # Provide the server process to the tests
    yield server_process
    
    # Clean up after the tests
    server_process.send_signal(signal.SIGTERM)
    server_process.wait(timeout=5)
    
    # If the server is still running, force kill it
    if server_process.poll() is None:
        server_process.kill()
        server_process.wait()
