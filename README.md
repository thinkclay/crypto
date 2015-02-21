# Crypto: Cryptography made Simple
A quick and dirty two-way encryption implementation for Objective-C and Swift


## Implementation
Implemantion in Swift could be a simple AuthHelper class which simplifies encrypting and decrypting strings:

```swift
final public class AuthHelper: NSObject
{
  public class func encrypt(input: String, password: String) -> (string: String?, data: NSData?)
  {
    let data = input.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: true)
    let encryptedData = Crypto.encryptData(data, password: password, error: nil)
    let encryptedString = encryptedData.base64EncodedStringWithOptions(NSDataBase64EncodingOptions(rawValue: 0))
    
    return (string: encryptedString, data: encryptedData)
  }
  
  public class func decrypt(input: String, password: String) -> (string: String?, data: NSData?)
  {
    let encryptedData = NSData(base64EncodedString: input, options: NSDataBase64DecodingOptions(rawValue: 0))
    let decryptedData = Crypto.decryptData(encryptedData, password: password, error: nil)
    let decryptedText = NSString(data: decryptedData, encoding: NSUTF8StringEncoding) as? String
    
    return (string: decryptedText, data: decryptedData)
  }
}
```

## Test
```swift
func testEncryptMatchesDecrypt()
{
  let encrypted = AuthHelper.encrypt(payload, password: password)
  let decrypted = AuthHelper.decrypt(encrypted.string, password: password)
  
  XCTAssertEqual(decrypted.string!, payload, "encrypt and decrypt should work with any password")
}
```
