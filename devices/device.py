from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
import random
import hashlib
from pathlib import Path
from eth_account import Account


# -------------------------------------------------
# 1. DEVICE IDENTITY
# -------------------------------------------------

device_name = "DEVICE_001"

# File where the device stores its private key
key_file = Path("device_private_key.pem")


# Load existing private key or create a new one
if key_file.exists():

    with open(key_file, "rb") as file:
        private_key = serialization.load_pem_private_key(
            file.read(),
            password=None
        )

else:

    private_key = ec.generate_private_key(ec.SECP256K1())

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    with open(key_file, "wb") as file:
        file.write(private_bytes)


# Generate public key
public_key = private_key.public_key()
# Get the raw 32-byte private key value
private_value = private_key.private_numbers().private_value
private_key_bytes = private_value.to_bytes(32, byteorder="big")

# Create Ethereum account
account = Account.from_key(private_key_bytes)

# Get Ethereum address
ethereum_address = account.address

# Convert public key to bytes
public_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.UncompressedPoint
)


# Create unique device ID from public key
device_id = hashlib.sha256(public_bytes).hexdigest()
# Convert Device ID to bytes32 format for Solidity
device_id_bytes32 = "0x" + device_id


print("IoT Device Identity Created")
print("----------------------------")
print("Device Name:", device_name)
print("Device ID:", device_id)
print("Device ID (bytes32):", device_id_bytes32)
print("Ethereum Address:", ethereum_address)

print("\nPublic Key:")
print(public_bytes.hex())


# -------------------------------------------------
# 2. SENSOR DATA SIMULATION
# -------------------------------------------------

temperature = round(random.uniform(20, 35), 2)
humidity = round(random.uniform(40, 80), 2)


print("\nSensor Data")
print("-----------")
print("Temperature:", temperature, "°C")
print("Humidity:", humidity, "%")


# -------------------------------------------------
# 3. CREATE MESSAGE
# -------------------------------------------------

message = f"{device_id}|{temperature}|{humidity}".encode()


# -------------------------------------------------
# 4. SIGN SENSOR DATA
# -------------------------------------------------

signature = private_key.sign(
    message,
    ec.ECDSA(hashes.SHA256())
)


print("\nDigital Signature")
print("-----------------")
print(signature.hex())
# Simulate tampered sensor data
tampered_message = f"{device_id}|99.99|99.99".encode()
# -------------------------------------------------
# 5. VERIFY DIGITAL SIGNATURE
# -------------------------------------------------

try:
    public_key.verify(
        signature,
        message,
        ec.ECDSA(hashes.SHA256())
    )

    print("\nAuthentication Result")
    print("--------------------")
    print("Signature is VALID")
    print("Device authenticated successfully.")

except Exception:
    print("\nAuthentication Result")
    print("--------------------")
    print("Signature is INVALID")
    print("Device authentication failed.")