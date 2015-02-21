Quick and simple security for Swift

As a cryptographer, I can tell you that often the best security is the simplest. The more obfuscated the implementation is, the easier it is to miss details and to create gaping holes in your security, or worse yet: skip security because the implementation is over your head. 

This library aims to make really basic security really easy to implement. I have collected and ported some code from [RNCryptor](https://github.com/RNCryptor/RNCryptor) and consolidated the methods down to some dead simple calls as well as created a simple getter/setter library for Keychain.

This library is for someone who just wants to store some simple data in a non-plaintext format. By using it, you acknowledge that it is not meant to be the most secure implementation and that you will use at your own risk.

## Install and Use
Drop the folder somewhere into your project. The library will be made available globall within your app.

Implemantion could be a simple AuthHelper class which simplifies encrypting and decrypting strings:

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

## With some tests to go along with it:
```swift
let password = "password"
let payload = "this is hogwash"

func testKeychainSet()
{
  let token = AuthHelper.encrypt(payload, password: password).string
  let save = Keychain.set("foo", value: payload)
  let get = Keychain.get("foo") as! String
  
  XCTAssertTrue(save, "should be able to set keychain string with key")
  XCTAssertNotNil(get, "should be able to retrieve save keychain string with key")
  XCTAssertEqual(get, payload, "retrieved keychain string payload should match original payload")
}

func testKeychainUnset()
{
  let delete = Keychain.delete("foo")
  
  XCTAssertTrue(delete, "should be able to unset keychain by key")
}
  
func testEncryptMatchesDecrypt()
{
  let encrypted = AuthHelper.encrypt(payload, password: password)
  let decrypted = AuthHelper.decrypt(encrypted.string, password: password)
  
  XCTAssertEqual(decrypted.string!, payload, "encrypt and decrypt should work with any password")
}
```
