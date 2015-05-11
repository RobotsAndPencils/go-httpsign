# go-httpsign
Go middleware for signing and verifying http requests via HMAC SHA256.

[![Build Status](https://travis-ci.org/RobotsAndPencils/go-httpsign.svg)](https://travis-ci.org/RobotsAndPencils/go-httpsign)

### Installing

    go get github.com/RobotsAndPencils/go-httpsign

### Using

    key := []byte("this is your key")
    hs := httpsign.New(key)

Using a custom header name:

    hs.HeaderName = "X-WHATEVERYOUWANT"

The library verifies that the time difference between generation of the signature and the time the server received the request is within reason. The default allows `6` seconds difference between client and server but is configurable:

    hs.SecondsAllowance = 10    // to set to 10 seconds

You can specify a "log hook" function that gets called whenever a failure happens in the Verify() handler.  This helps
debugging deployments when keys and clocks do not match up.

    hs.LookHook = func(msg string) {
        log.Printf("HTTPSIGN ERROR: %s\n", msg)
    }

#### A client making a signed request

    // content is the value of the content to sign
    // It must be something you send, like another header that is
    // agreed upon
    content := "the value of the content you will sign"
    header := hs.GenerateHeaderValue(content)
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


#### Testing

    key := []byte("does not matter")
    hs := httpsign.New(key)
    hs.DisableVerify = true

Adding the Verify() middleware can make it really annoying to test a local service.  You can optionally set
`DisableVerify` to `true` in order to simplify the Verify() handler such that it always determines the request is valid,
regardless whether the signaturate header is valid or even present.


### Contributing

    git clone git@github.com:RobotsAndPencils/go-httpsign.git
    make init
    make test

### Contact

[![Robots & Pencils Logo](http://f.cl.ly/items/2W3n1r2R0j2p2b3n3j3c/rnplogo.png)](http://www.robotsandpencils.com)

Made with :heart: by Robots & Pencils ([@robotsNpencils](https://twitter.com/robotsNpencils))

#### Maintainers

- [Mike Brevoort](http://github.com/mbrevoort) ([@mbrevoort](https://twitter.com/mbrevoort))
