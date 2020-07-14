String jwt = '{"iss": "CONNECTED_APP_CONSUMER_KEY","sub": "USER_NAME","aud": "https://login.salesforce.com","exp": "'+System.now().addMinutes(5).getTime()+'"}'; 

String paramvalue = EncodingUtil.base64Encode(Blob.valueOf(jwt)); 

 String finalString = EncodingUtil.base64Encode(Blob.valueOf('{"alg":"RS256"}'))+'.'+paramvalue; 

 Blob privateKey = EncodingUtil.base64Decode('PRIVATE_KEY_FROM_CERTIFICATE_GENERATION'); //Should be without any line break

 Blob signature = Crypto.sign('RSA-SHA256', Blob.valueOf(finalString), privateKey); 

String output = encodingUtil.base64Encode(signature); 

output = output.replaceAll('\\+', '-'); 

output = output.replaceAll('/', '_'); 

String assertionString = finalString + '.'+output; 

System.debug(assertionString); 
