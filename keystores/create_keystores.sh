#! /usr/bin/bash -i

clear

# ################################################
#                                          Colors                                             #
# ################################################
txtrst='\e[0m'         # Text Reset
txtgrn='\e[0;32m'    # Green
txtred='\e[0;31m'    # Red

# ################################################
#               Define the Keystores for Alice and Bob                             #
#                                                                                               #
#  Remark: We make an alias to shorten the commands' syntax.            #
# ################################################
KS_PASS=k3y5t0r3
A_KEYSTORE_ARGS=(-storepass ${KS_PASS} -keystore alice.jks)
alias aktool='keytool ${A_KEYSTORE_ARGS[*]}'
B_KEYSTORE_ARGS=(-storepass ${KS_PASS} -keystore bob.jks)
alias bktool='keytool ${B_KEYSTORE_ARGS[*]}'

# ################################################
#                                   Entities Definition                                     #
# ################################################
PRV_KEY_PASS=123456
A_DNAME="cn=Alice Sender, ou=IT, o=CONTOSO, c=IL"
B_DNAME="cn=Bob Receiver, ou=HR, o=ACME, c=US"
A_ARGS=(-alias alice -keypass ${PRV_KEY_PASS})
B_ARGS=(-alias bob -keypass ${PRV_KEY_PASS})

# ################################################
# Remark: -keyalg RSA ==> -keysize 2048 and -sigalg SHA256withRSA.  #
# ################################################
COMMON_ARGS=(-keyalg RSA)
ERROR=${txtred}ERROR${txtrst}
INFO=${txtgrn}INFO${txtrst}

echo -e [$INFO] "Generating key-pairs for Alice..."
aktool -genkeypair \
   -dname "${A_DNAME}" \
   ${A_ARGS[*]} \
   ${COMMON_ARGS[*]} \
&& echo -e [$INFO] "Generating key-pairs for Bob..."
bktool -genkeypair \
   -dname "${B_DNAME}" \
   ${B_ARGS[*]} \
   ${COMMON_ARGS[*]} \
&& echo -e [$INFO] "Alice is sending her certificate to Bob..."
aktool -exportcert -rfc ${A_ARGS[*]} | 
bktool -importcert -trustcacerts -noprompt ${A_ARGS[*]} \
&& echo -e [$INFO] "Bob got Alice's certificate..."
echo -e [$INFO] "Bob is asking Alice to sign Bob's Certificate..."
bktool -exportcert -rfc ${B_ARGS[*]} | 
aktool -importcert -trustcacerts -noprompt ${B_ARGS[*]} \
&& echo -e [$INFO] "Alice got Bob's certificate..."

# ################################################
#                       Print the result of the whole operation.                    #
# ################################################
if [ $? == 0 ]
then
    echo -e [$INFO] "Printing keystores contents..."
    aktool -list -v; bktool -list -v
    echo -e [$INFO] "Operation Succeeded."
    exit 0
else
    echo -e [$ERROR] "Operation Failed."
    exit 1
fi
