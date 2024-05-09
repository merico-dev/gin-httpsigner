
works with [merico-dev/httpsign](https://github.com/merico-dev/httpsign)

#### usage
```golang
func main() {

	req, err := http.NewRequestWithContext(context.Background(), "POST", requestURL, strings.NewReader(sampleBodyContent))
	if err != nil {
		panic(err)
	}

	s := NewGinHttpSigner(
		httpsign.KeyID("key-id"), // keep it the same with gin middlewares config
		&httpsign.Secret{
			Key:       "key-secret",  // key secret, read it from env
			Algorithm: &crypto.HmacSha512{}, // keep it the same with gin middlewares config
		}, []string{})
	if err := s.SignRequest(req); err != nil {
		panic(err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	fmt.Println(resp.StatusCode)
}

```