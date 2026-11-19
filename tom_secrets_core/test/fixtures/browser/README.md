# Browser password exports (synthetic)

Demo data only. The layouts the browsers write:

- `chrome.csv`: Chrome's and Edge's export (`name,url,username,password,note`),
  with a quoted two-line note.
- `firefox.csv`: Firefox's export (`url`, `username`, `password`,
  `httpRealm`, `formActionOrigin`, `guid` and its times; no title).
- `safari.csv`: Safari's and the macOS Passwords app's export (`Title`,
  `URL`, `Username`, `Password`, `Notes`, `OTPAuth`).
