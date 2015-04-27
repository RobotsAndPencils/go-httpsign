# go-httpsign
Go middleware for signing and verifying http requests via HMAC SHA256.

### Installing

    go get github.com/RobotsAndPencils/go-httpsign

### Using

    key := []byte("this is your key")
    hs := httpsign.New(key)

Using a custom header name:

    hs.HeaderName = "X-WHATEVERYOUWANT"

The library verifies that the time difference between generation of the signature and the time the server received the request is within reason. The default allows `6` seconds difference between client and server but is configurable:

    hs.SecondsAllowance = 10    // to set to 10 seconds

#### A client making a signed request

    // content is the value of the content to sign
    // It must be something you send, like another header that is
    // agreed upon
    content := "the value of the content you will sign"
    header := hs.GenerateHeaderValue(value)
    req, err = http.NewRequest("GET", url, nil)
    req.Header.Set(hs.HeaderName, header)
    resp, err = http.DefaultClient.Do(req)


#### A server receiving a request

    // Assume you are sending the content to be signed as a header
    // named `REQUEST-ID`
    getValue := func(w http.ResponseWriter, r *http.Request) string {
        return r.Header.Get("REQUEST-ID")
    }

    h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // your foo http handler
    })

    http.Handle("/foo", hs.Verify(h, getValue))


### Contributing

    git clone git@github.com:RobotsAndPencils/go-httpsign.git
    make init
    make test

