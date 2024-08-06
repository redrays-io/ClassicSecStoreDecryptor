# ClassicSecStoreDecryptor

ClassicSecStoreDecryptor is a Java-based tool designed to decrypt SecStore properties and key files. It provides both automatic and manual decryption modes, making it a versatile utility for accessing encrypted information stored in SecStore files.

## Features

- Automatic decryption of all properties in a SecStore file
- Manual decryption of specific properties
- Support for custom file paths for properties and key files
- Compatibility with different versions of SecStore encryption

## Prerequisites

To run ClassicSecStoreDecryptor, you need:

- Java Development Kit (JDK) 8 or higher
- IAIK security provider library

## Usage

```
java -jar ClassicSecStoreDecryptor.jar -s <SID> [-a | -m <parameter>] [/path/to/propertiesFile /path/to/keyFile]
```

### Options:

- `-s <SID>`: Specify the SID (System ID)
- `-a`: Automatic decode (decrypts all properties)
- `-m <parameter>`: Manual decode (requires parameter name)

### File paths (optional):

- `propertiesfile`: Full path to the SecStore.properties file (default: 'SecStore.properties' in the current directory)
- `keyfile`: Full path to the SecStore.key file (default: 'SecStore.key' in the current directory)

### Examples:

1. Decrypt a specific key for SID 'J01':
   ```
   java -jar ClassicSecStoreDecryptor.jar -s J01 -m jdbc/pool/SID
   ```

2. Automatically decrypt all properties for SID 'J01':
   ```
   java -jar ClassicSecStoreDecryptor.jar -s J01 -a
   ```

3. Automatically decrypt with custom file locations:
   ```
   java -jar ClassicSecStoreDecryptor.jar -s J01 -a SecStore.properties SecStore.key
   ```

## Building from Source

1. Clone the repository:
   ```
   git clone https://github.com/redrays-io/ClassicSecStoreDecryptor.git
   ```

2. Navigate to the project directory:
   ```
   cd ClassicSecStoreDecryptor
   ```

3. Compile the Java source files:
   ```
   javac -cp .:path/to/iaik/library.jar SecStore.java
   ```

4. Create a JAR file:
   ```
   jar cvfe ClassicSecStoreDecryptor.jar SecStore *.class
   ```

## Contributing

Contributions to ClassicSecStoreDecryptor are welcome. Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is intended for legitimate use only. Ensure you have the necessary permissions before decrypting any SecStore files.
