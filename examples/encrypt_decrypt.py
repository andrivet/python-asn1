from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import base64

def load_private_key(filepath):
    """ Load an RSA private key from a PEM file. """
    with open(filepath, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,  # No password
            backend=default_backend()
        )
    return private_key

def decrypt_message(private_key, ciphertext):
    """ Decrypt a message using the provided RSA private key. """
    decrypted_message = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message

def main():
    # Path to the RSA private key in PEM format
    key_path = 'complete_private_key.pem'
    # Encoded ciphertext (base64)
    encoded_ciphertext = 'LvTAlRgHHPM0VA7vz1ZnlfAh4kOJR6okqlujlKyg5GTDxMV8BdtfJQnswn9VZk/uOnxxEgy+rjDd bstRonOBpDE/CFB1ozIZDP0+KA2HkgruBj7cGDn7EWyIJGS8EBAQZ+/v4RYNidV7i867x/aoNdQV NajzRM0fnetb3bnW2Ws='

    # Load the RSA private key
    private_key = load_private_key(key_path)

    # Decode the ciphertext from Base64
    ciphertext = base64.b64decode(encoded_ciphertext)

    # Decrypt the ciphertext
    decrypted_message = decrypt_message(private_key, ciphertext)

    # Print the decrypted message
    print("Decrypted message:", decrypted_message.decode())

if __name__ == "__main__":
    main()
