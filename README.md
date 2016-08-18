# g2pa

Temporary password generation for two-factor authentication. Works with Google
Authenticator mobile app.


## Sample usage
1. Get Google Authenticator
2. Tap on 'Set up account'
3. Pick 'Enter provided code'
4. Enter account name 'GoLang console'
5. Enter key 'PT2KHGTK7YQ3EVIK'
6. Save
7. Run code from below in the console. Temporary password from the console and
from the app will match

```
package main

import (
    "fmt"
    "github.com/andrewromanenco/g2fa"
)

func main() {
    //key, err := g2fa.GenerateKey()
    //skey := g2fa.EncodeKey(key)
    skey := "PT2KHGTK7YQ3EVIK"
    key, err := g2fa.DecodeKey(skey)
    
    if err != nil {
        panic(err)
    }
    code, err := g2fa.GetTimedAuthCode(key)
    if err != nil {
        panic(err)
    }
    fmt.Println("Key: ", skey)
    fmt.Println("Temp code: ", code)
}
```