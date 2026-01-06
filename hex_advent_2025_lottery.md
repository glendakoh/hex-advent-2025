# Hex Advent 2025 — Christmas Lottery

**Category:** Reverse
**Level:** Hard

---

## Summary of Program and Key Notes

 We are given an apk file, and by reversing it in jadx, we can understand the activities available. 

Below is the manifest file and we notice that com.christmas.lottery.MainActivity is the activity started when the app launches.

```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    android:versionCode="1"
    android:versionName="1.0"
    android:compileSdkVersion="34"
    android:compileSdkVersionCodename="14"
    package="com.christmas.lottery"
    platformBuildVersionCode="34"
    platformBuildVersionName="14">
    <uses-sdk
        android:minSdkVersion="29"
        android:targetSdkVersion="34"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>
    <uses-permission android:name="com.google.android.providers.gsf.permission.READ_GSERVICES"/>
    <permission
        android:name="com.christmas.lottery.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"
        android:protectionLevel="signature"/>
    <uses-permission android:name="com.christmas.lottery.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"/>
    <application
        android:theme="@style/Theme.ChristmasLottery"
        android:label="@string/app_name"
        android:icon="@mipmap/ic_launcher"
        android:name="com.christmas.lottery.ChristmasLotteryApp"
        android:allowBackup="true"
        android:supportsRtl="true"
        android:extractNativeLibs="false"
        android:fullBackupContent="@xml/backup_rules"
        android:roundIcon="@mipmap/ic_launcher_round"
        android:appComponentFactory="androidx.core.app.CoreComponentFactory"
        android:dataExtractionRules="@xml/data_extraction_rules">
        <activity
            android:theme="@style/Theme.ChristmasLottery"
            android:label="@string/app_name"
            android:name="com.christmas.lottery.MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
```
---

## 1. Installing and Launching App

Using adb, I installed the app on a rooted android emulator. Launching the app, we see:

![main activity](./app.png)

Tracing the reversed app java code in jadx we see that clicking on the button, Submit Ticket Code, eventually makes a post request wiith the following code:

```java
case 10:
    try {
        W1.o oVar2 = new W1.o();
        oVar2.a("ticketCode", (String) ((C0291B) obj).f3352b);
        oVar2.a("idToken", (String) this.f3545b);

        W1.p pVar2 = new W1.p(oVar2.f1030a, oVar2.f1031b);
        W1.z zVar2 = new W1.z();

        StringBuilder sb2 = new StringBuilder();
        String str = ((MainActivity) ((C0291B) obj).f3353c).backendUrl;
        sb2.append(str);
        sb2.append("/validate");

        zVar2.d(sb2.toString());
        zVar2.c("POST", pVar2);

        C0339x a4 = zVar2.a();
        xVar = ((MainActivity) ((C0291B) obj).f3353c).httpClient;
        c3 = new a2.i(xVar, a4, false).c();

        ((MainActivity) ((C0291B) obj).f3353c)
            .runOnUiThread(new S.a(this, c3, new JSONObject(c3.f930j.c()), 5));

        c3.close();
        return;
    } catch (Exception e) {
        ((MainActivity) ((C0291B) obj).f3353c)
            .runOnUiThread(new RunnableC0314k(9, this, e));
        return;
    }
```

The request sends:

1. ticketCode (user input)
2. idToken (Firebase authentication token)
---

## 2. Frida, intercepting the idToken

Since the emulator is rooted, I pushed frida-server and injected a Frida script
to intercept the POST request.

```js
Java.perform(function () {

    console.log("[*] Frida POST interceptor loaded");

    var Z = Java.use("W1.z");

    // ---- Hook URL ----
    Z.d.overload("java.lang.String").implementation = function (url) {
        console.log("\n[+] URL:");
        console.log("    " + url);
        return this.d(url);
    };

    // ---- Hook POST ----
    Z.c.overload("java.lang.String", "M0.a").implementation = function (method, body) {
        console.log("\n[+] HTTP Method: " + method);

        try {
            // Dump fields dynamically (safe with obfuscation)
            var fields = body.getClass().getDeclaredFields();
            for (var i = 0; i < fields.length; i++) {
                fields[i].setAccessible(true);
                var name = fields[i].getName();
                var value = fields[i].get(body);
                console.log("    " + name + " = " + value);
            }
        } catch (e) {
            console.log("[!] Failed to dump POST body: " + e);
        }

        return this.c(method, body);
    };

});
```

Running this while submitting a ticket successfully intercepts the request:

![intercepted request](./request.png)

Now we just need to get the valid ticket code.
---

## 3. Ticket Code

Analysing the other parts of main activity we see a code that allows us to generate our own token.

```java
private int calculateChecksum(String str) {
    int i3 = 0;
    for (char c3 : str.toCharArray()) {
        i3 = (Character.isDigit(c3) ? Character.getNumericValue(c3) : c3 - '@') + i3;
    }
    return i3 % 10;
}

private String generateTicketCode() {
    StringBuilder sb = new StringBuilder();
    for (int i3 = 0; i3 < 3; i3++) {
        sb.append("ABCDEFGHJKLMNPQRSTUVWXYZ".charAt((int) ((this.secretSeed >> (i3 * 3)) % 24)));
    }
    sb.append("-");
    for (int i4 = 0; i4 < 4; i4++) {
        sb.append("0123456789".charAt((int) ((this.secretSeed >> ((i4 * 4) + 9)) % 10)));
    }
    sb.append("-");
    for (int i5 = 0; i5 < 2; i5++) {
        sb.append("ABCDEFGHJKLMNPQRSTUVWXYZ".charAt((int) ((this.secretSeed >> ((i5 * 5) + 25)) % 24)));
    }

    sb.append("0123456789".charAt(calculateChecksum(sb.toString().replace("-", "")) % 10));
    return sb.toString();
}
```

Using this logic we can derive the ticket code that would work! I got chatgpt to create a python script that prints out the code:

```py
LETTERS = "ABCDEFGHJKLMNPQRSTUVWXYZ"
DIGITS = "0123456789"

def calculate_checksum(s: str) -> int:
    total = 0
    for c in s:
        if c.isdigit():
            total += int(c)
        else:
            total += ord(c) - ord('@') 
    return total % 10


def generate_ticket_code(secret_seed: int) -> str:
    parts = []
    for i in range(3):
        idx = (secret_seed >> (i * 3)) % 24
        parts.append(LETTERS[idx])
    parts.append("-")
    for i in range(4):
        idx = (secret_seed >> ((i * 4) + 9)) % 10
        parts.append(DIGITS[idx])
    parts.append("-")
    for i in range(2):
        idx = (secret_seed >> ((i * 5) + 25)) % 24
        parts.append(LETTERS[idx])
    without_dashes = "".join(parts).replace("-", "")
    checksum_digit = calculate_checksum(without_dashes) % 10
    parts.append(DIGITS[checksum_digit])

    return "".join(parts)

ticket_code=generate_ticket_code(7546796)
print(ticket_code)
```
**Ticket Code:**
WFG-9173-AA8
---

## 4. Post Request

Having intercepted the post request with frida, we can mimic the exact same post request in curl but WITH the valid ticket code we recovered!

```bash
curl -X POST "https://us-central1-christmas-lottery-b838b.cloudfunctions.net/validate" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "ticketCode=WFG-9173-AA8" \
  --data-urlencode "idToken=eyJhbGciOiJSUzI1NiIsImtpZCI6Ijk1MTg5MTkxMTA3NjA1NDM0NGUxNWUyNTY0MjViYjQyNWVlYjNhNWMiLCJ0eXAiOiJKV1QifQ.eyJwcm92aWRlcl9pZCI6ImFub255bW91cyIsImlzcyI6Imh0dHBzOi8vc2VjdXJldG9rZW4uZ29vZ2xlLmNvbS9jaHJpc3RtYXMtbG90dGVyeS1iODM4YiIsImF1ZCI6ImNocmlzdG1hcy1sb3R0ZXJ5LWI4MzhiIiwiYXV0aF90aW1lIjoxNzY1NjA4MjQ2LCJ1c2VyX2lkIjoicVU1Nmg1Ynh3cFh6YVlpOUdYdGFFbTFVazAwMyIsInN1YiI6InFVNTZoNWJ4d3BYemFZaTlHWHRhRW0xVWswMDMiLCJpYXQiOjE3NjU2MDgyNDYsImV4cCI6MTc2NTYxMTg0NiwiZmlyZWJhc2UiOnsiaWRlbnRpdGllcyI6e30sInNpZ25faW5fcHJvdmlkZXIiOiJhbm9ueW1vdXMifX0.elCrwlE7m8uVepUCLsS9rymsXoiRN4mdapI4H4gVTxxDNyTzrLXd_zyEiOR132X1kk5mG_Phkr_l83Taj2YRwXObWu9nf1xqvm5JuTu-7xty1hVduUrUWXgjEm1vqPzujwH1CTi23SgUJtErGJzIivPhFNQxfE5FU9g9zM2jjFiWIu_NKTeg2QttBVUqjX7R-SesOIhBuf7dbLHS5n8fQVzUJBXisa7Nu9I777iQ3_msWKTaUJgkA_zfQHOr1UzcGB16BZn5pRJm162G2D28gcJMxbMo_HNkH7dJiUlXZhB8No2BZIHfsAed7lU9SNcDL128sj-veioy8DVmQVnVmQ"
```

Andddd yup we got our flag in the response!

```json
{"flag":"HEX{Fr1d4_i5_S4nT4s_b3sT_fRi3nD}","message":"Valid ticket!"}
```

**Flag Obtained:**
```
HEX{Fr1d4_i5_S4nT4s_b3sT_fRi3nD}
```

---
