import subprocess

"""
Helper to perform CLI operations on BMv2 switches.
Workaround for register read/write given that the P4Runtime API does not support it.
"""

def register_write(thrift_port, reg_name, index, value):
    """
    :param thrift_port: The Thrift port of the BMv2 switch.
    :param reg_name: The name of the register (e.g. "MyIngress.reg").
    :param index: The index in the register to write to.
    :param value: The integer value to write.
    """
    cmd = f"register_write {reg_name} {index} {value}"
    proc = subprocess.run(
        ["simple_switch_CLI", "--thrift-port", str(thrift_port)],
        input=cmd + "\n",
        text=True,
        capture_output=True
    )
    if proc.returncode != 0:
        raise RuntimeError(f"CLI write failed: {proc.stderr}")
    #print(cmd, thrift_port)
    #print(f"CLI write output: {proc.stdout}")


def register_read(thrift_port, reg_name, index):
    """
    :param thrift_port: The Thrift port of the BMv2 switch.
    :param reg_name: The name of the register (e.g. "MyIngress.reg").
    :param index: The index in the register to read from.
    :return: The integer value read from the register.
    """
    cmd = f"register_read {reg_name} {index}"
    proc = subprocess.run(
        ["simple_switch_CLI", "--thrift-port", str(thrift_port)],
        input=cmd + "\n",
        text=True,
        capture_output=True
    )
    if proc.returncode != 0:
        raise RuntimeError(f"CLI read failed: {proc.stderr}")

    #print(cmd, thrift_port)
    #print(f"CLI read output: {proc.stdout}")
    for line in proc.stdout.splitlines():
        if "=" in line:
            return int(line.split("=")[-1].strip())
    raise ValueError(f"Unexpected CLI output: {proc.stdout}")
