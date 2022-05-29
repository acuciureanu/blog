---
title: "This is how I solved the January XSS challenge @ intigriti.com"
date: 2022-01-18T13:26:17+02:00
---


**Challenge**: `https://challenge-0122.intigriti.io/`

This challenge was very interesting because it was my first time hunting for an XSS while having to deal with React and some strange javascript obfuscation that I'd have to figure out first.

## Recon

I initially started looking at the javascript code by using the `Developers Tools` in `Chrome` and I noticed that the  `identifiers`  object was defined in  **_routes.js_**.

After I looked closely, I noticed that the values of the object's properties are BASE64 encoded strings.

![Source Map](/images/intigriti-jan-xss-challenge-2022/identifiers.jpg)

## Figuring out obfuscation

I navigated under `js/pages/` and found out that the code there is obfuscated and that the signatures of the functions contain property names from our `identifiers` object and that `window.atob()` is used to decode the BASE64 encoded values.

![Obfuscated code](/images/intigriti-jan-xss-challenge-2022/pages.jpg)

For decoding all the BASE64 encoded strings I wrote some easy javascript code which can be ran in browser's console.

```javascript
const identifiers = {
  I0x1: "UmVzdWx0",
  I0x2: "cGF5bG9hZEZyb21Vcmw=",
  I0x3: "cXVlcnlSZXN1bHQ=",
  I0x4: "bG9jYXRpb24=",
  I0x5: "c2VhcmNo",
  I0x6: "Z2V0",
  I0x7: "cGF5bG9hZA==",
  I0x8: "cmVzdWx0",
  I0x9: "X19odG1s",
  I0xA: "PGgxIHN0eWxlPSdjb2xvcjogIzAwYmZhNSc+Tm90aGluZyBoZXJlITwvaDE+",
  I0xB: "aGFuZGxlQXR0cmlidXRlcw==",
  I0xC: "ZWxlbWVudA==",
  I0xD: "Y2hpbGQ=",
  I0xE: "Y2hpbGRyZW4=",
  I0xF: "YXR0cmlidXRlcw==",
  I0x10: "Z2V0QXR0cmlidXRl",
  I0x11: "ZGF0YS1kZWJ1Zw==",
  I0x12: "c2FuaXRpemVIVE1M",
  I0x13: "aHRtbE9iag==",
  I0x14: "dGVtcGxhdGU=",
  I0x15: "c2FuaXRpemU=",
  I0x16: "Y3JlYXRlRWxlbWVudA==",
  I0x17: "aW5uZXJIVE1M",
  I0x18: "YXBwZW5kQ2hpbGQ=",
  I0x19: "Z2V0RWxlbWVudHNCeVRhZ05hbWU=",
  I0x1A: "Y29udGVudA==",
  I0x1B: "cmVtb3ZlQ2hpbGQ=",
  I0x1C: "SG9tZQ==",
  I0x1D: "c2V0UGF5bG9hZA==",
  I0x1E: "ZWRpdG9yUmVm",
  I0x1F: "bmF2aWdhdGU=",
  I0x20: "aGFuZGxlU3VibWl0",
  I0x21: "ZXZlbnQ=",
  I0x22: "cHJldmVudERlZmF1bHQ=",
  I0x23: "L3Jlc3VsdD9wYXlsb2FkPQ==",
  I0x24: "dmFsdWU=",
  I0x25: "a2V5",
  I0x26: "VGFi",
  I0x27: "c2hpZnRLZXk=",
  I0x28: "c2V0UmFuZ2VUZXh0",
  I0x29: "ICAgIA==",
  I0x2A: "c2VsZWN0aW9uU3RhcnQ=",
  I0x2B: "ZW5k",
  I0x2C: "bGluZVN0YXJ0",
  I0x2D: "c3RhcnQ=",
  I0x2E: "bGVuZ3Ro",
  I0x2F: "c2xpY2U=",
  I0x30: "c2V0U2VsZWN0aW9uUmFuZ2U=",
  I0x31: "Cg==",
  I0x32: "Ym9keQ==",
  I0x33: "dGFyZ2V0",
  I0x34: "Y3VycmVudA==",
};

Object.keys(identifiers).reduce((acc, key) => { acc[key] = window.atob(identifiers[key]); return acc }, {});
```

We passed a reducer to the [reduce()](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/Reduce) function which decodes the BASE64 values from `identifiers` and then returns a transformed object which will help us with the deobfuscation.

And here's how it should look for you.

![Decoded Strings](/images/intigriti-jan-xss-challenge-2022/decoded.jpg)

I thought about writing a tool for mass deobfuscation, but since there were only a couple of javascript files it took me only a few minutes to deobfuscate both `index.js` files under `pages` and figure out this whole challenge.

After manually deobfuscating all the interesting files, I found the issue under `/js/pages/I0x1/index.js`.

The function signature `function I0xB(I0xC)` translates to `function handleAttributes(element)`:

```javascript
function handleAttributes(element) {
  for (const child of child['children']) {
    if ("data-debug" in child['attributes']) {
      new Function(
        child 'getAttribute'
      )();
    }

    handleAttributes(child);
  }
}
```

## Identify XSS

Hm... So, when this `handleAttributes` function is called by passing an `element` as an argument, if there's a `data-debug` attribute set on any of the child elements then a new function is created using [new Function()](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function/Function) and the official documentation suggests that calling the constructor directly is not exactly a best practice.

> The Function constructor creates a new Function object. Calling the constructor directly can create functions dynamically, but suffers from security and similar (but far less significant) performance issues to [Global_Objects/eval](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval). However, unlike eval, the Function constructor creates functions which execute in the global scope only.

## Exploit flaw

Now that I knew I had to play around with the `data-debug` attribute, I had to set it to something which would give us the desired result, so I managed to use the `<h1>` HTML tag which is used to display a successful result.

So, here's my payload which triggers `alert(document.domain)` and then the HTML element will display the message `Yay!` on page:

**Payload**: `<h1 style='color: #00bfa5' data-debug='javascript:alert(document.domain)'>Yay!</h1>`

**Browser versions (latest):**

- Chrome: Version 97.0.4692.71 (Official Build) (64-bit)

- Firefox: 96.0

## Results

### Chrome

![Chrome](/images/intigriti-jan-xss-challenge-2022/chrome.jpg)

### Firefox

![Firefox](/images/intigriti-jan-xss-challenge-2022/firefox.jpg)

## Surprise

So, after you click the `OK` button from the alert dialog it closes and you get a `Yay!` message because everything worked as expected.

![Yay](/images/intigriti-jan-xss-challenge-2022/yay.jpg)

Thank you for reading my write-up.

Hope you enjoyed it. :)
