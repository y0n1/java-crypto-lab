# **CS3536: Building Secure Applications**
---

## Steps Performed:

### 1. Generate a keystore and key pair for Alice:
> `keytool -genkeypair -alias alice -keyalg RSA -keypass 4l1c3= -keystore alice.jks -storepass 4l1c3=k3y5t0r3`

### 2. Generate a keystore and a key pair for Bob:
> `keytool -genkeypair -alias bob -keyalg RSA -keypass b0b=== -keystore bob.jks -storepass b0b===k3y5t0r3`

### 3. Exchange the Self-Signed Certificates:

1. > `keytool -exportcert -keystore alice.jks -storepass 4l1c3=k3y5t0r3 -alias alice | keytool -importcert -keystore bob.jks -storepass b0b===k3y5t0r3 -alias alice -trustcacerts -noprompt`
2. > `keytool -keystore bob.jks -storepass b0b===k3y5t0r3 -alias bob -exportcert | keytool -importcert -keystore alice.jks -storepass 4l1c3=k3y5t0r3 -alias bob -trustcacerts -noprompt`
