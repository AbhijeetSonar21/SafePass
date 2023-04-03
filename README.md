# SafePass
Intel SGX based password manager application in Rust, focusing on enhanced security through hardware-based memory encryption and access control within a secure enclave. Moreover, successfully implemented a storage system and integrated 2FA, resulting in a reliable and secure password management solution for users.

To set up the environment for running the SafePass code, it is required to have a Docker environment from the official Apache Teaclave SGX SDK repository available at [https://github.com/apache/incubator-teaclave-sgx-sdk] Additional information on setting up the Docker environment can be found on the provided link.

Once the Docker environment is set up, the SafePass code needs to be added to the Docker environment. The code can be added by copying it to the root directory of the Docker container.

To run the SafePass code, navigate to the bin directory using the command prompt within the Docker container. Then, run the following command:

```
make SGX_MODE=SW
cd bin
./app
```

This command compiles the SafePass code and sets the SGX_MODE environment variable to SW, which is required to run the code in the software mode. Finally, the ./app command is executed to run the SafePass application.
