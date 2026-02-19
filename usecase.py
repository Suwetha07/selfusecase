import psutil
import platform
cpu = psutil.cpu_percent(interval=1)
mem = psutil.virtual_memory()

disk = psutil.disk_usage("/")

os_name = platform.system()
kernel = platform.release()

print(f"OS: {os_name} | Kernel: {kernel}")
print(f"CPU Usage: {cpu}% | Memory Usage: {mem.percent}%")
print(f"Disk Usage: {disk.percent}% ({disk.used // (1024**3)} / {disk.total // (1024**3)} GB)")
