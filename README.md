# wso2-am-OAuth-Encrypting-Client

This simple java client can be used to encrypting OAuth2 tokens when the product has been already running for some time. 
This will encrypt the existing data without breaking the product's functionality 

### Testing

As for now I have tested this most common workflows including
1. Generate keys/secrets
2. Generate JWT/Opaque tokens 
3. Invoke APIs using existing tokens
4. Generate new tokens using refresh tokens 
5. Request new tokens with Authentication codes that were created before encypting (Failed due to expired auth codes - expected)
6. Create new APIs/Applications and use them
7. Delete existing ones 


As for now this client is only tested with APIM 3.1.0.342 so it may not work with other versions (Specially 4.x products). Only the RSA/ECB/OAEPwithSHA1andMGF1Padding encryption algorithm is tested.

#### Not recommended to use in production enviornments and this code is only a reference material for creating a proper encryption tool 

### How to use 

1. Download the code.
2. Download the mysql driver https://downloads.mysql.com/archives/c-j/ and copy it to the source code directory - tested with 8.4.0.
4. Change the configs in `dbencrypttool.properties` accordingly (DB information, Encryption algorithm)
4. Stop the running APIM.
5. Run the command `java -cp ./mysql-connector-j-8.4.0.jar DBEncryptTool.java`. This will encrypt the columns mentioned in `dbencrypttool.properties` file. 
6. Turn on encryption in APIM [1].
7. Start the pack. 


#### Important: Make sure to backup your databases before running this Java client 


### Resources

[1] [https://apim.docs.wso2.com/en/3.1.0/learn/api-security/oauth2/encrypting-oauth2-tokens/#:~:text=use%20this%20key.-,Warning,-It%20is%20recommended](https://apim.docs.wso2.com/en/3.1.0/learn/api-security/oauth2/encrypting-oauth2-tokens/#:~:text=use%20this%20key.-,Warning,-It%20is%20recommended)

[2] [WSO2 APIM Encryption code](https://github.com/wso2/carbon-crypto-service/blob/53f3deda87ce11fc2602992fa2df72ffaaa67ac0/components/org.wso2.carbon.crypto.provider/src/main/java/org/wso2/carbon/crypto/provider/KeyStoreBasedInternalCryptoProvider.java#L78)
