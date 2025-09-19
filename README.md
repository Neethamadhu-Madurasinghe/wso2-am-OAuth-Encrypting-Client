# wso2-am-OAuth-Encrypting-Client

This simple java client can be used to encrypting OAuth2 tokens when the product has been already running for some time. 
This will encrypt the existing data without breaking the product's functionality 

### Testing

Currently I have tested this most common workflows including
1. Generate keys/secrets
2. Generate JWT/Opaque tokens 
3. Invoke APIs using existing tokens
4. Generate new tokens using refresh tokens 
5. Request new tokens with Authentication codes that were created before encypting (Failed due to expired auth codes - expected)
6. Create new APIs/Applications and use them
7. Delete existing ones 

As for now this client is only tested with APIM 3.1.0.342 so it may not work with other versions (Specially 4.x products)

#### Not recommended to use in production enviornments and this code is only a reference material for creating a proper encryption tool 

### How to use 

1. Download the code
2. Download the mysql driver https://downloads.mysql.com/archives/c-j/ and copy it to the source code directory - tested with 8.4.0
4. Change the configs in `dbencrypttool.properties` accordingly 
3. Run the command `java -cp ./mysql-connector-j-8.4.0.jar DBEncryptTool.java` 

#### Important: Make sure to backup your databases before running this Java client 


