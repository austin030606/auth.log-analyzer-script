awk 'BEGIN {
    failedUserCnt = 0;
    failedIpCnt = 0;
    failedUser[0] = "";
    failedIp[0] = "";
    failedCntOfUser[""] = 0;
    failedCntOfIp[""] = 0;
    prevUser = "";
    prevIp = "";
    prevIllegalUser = 0;
}
/PAM:/{
    illegalUser = 0;
    if (NF == 13) {
        user = $11;
        ip = $13;
    } else {
        illegalUser = 1;
        ip = $15;
    }
    foundUser = 0;
    foundIp = 0;
    userIndex = 0;
    ipIndex = 0;
    if(illegalUser == 0) {
        for (i = 1; i <= failedUserCnt; i++) {
            if (foundUser == 0) {
                if (failedUser[i] == user) {
                    foundUser = 1;
                    userIndex = i;
                }
            }
        }
        if (foundUser == 0) {
                failedUserCnt++;
                userIndex = failedUserCnt;
                failedUser[userIndex] = user;
        }
        failedCntOfUser[user]++;
    }
    for (i = 1; i <= failedIpCnt; i++) {
        if (foundIp == 0) {
            if (failedIp[i] == ip) {
                foundIp = 1;
                ipIndex = i;
            }
        }
    }
    if (foundIp == 0) {
        failedIpCnt++;
        ipIndex = failedIpCnt;
        failedIp[ipIndex] = ip;
    }
    failedCntOfIp[ip]++;
    prevUser = user;
    prevIp = ip;
    prevIllegalUser = illegalUser;
}
/syslogd/{
    repetition = $9;
    if(prevIllegalUser == 0) {
        for(i = 1; i <= repetition; i++) {
            failedCntOfUser[prevUser]++;
        }
    }
    for(i = 1; i <= repetition; i++) {
        failedCntOfIp[prevIp]++;
    }
}
/sudo/{
    user = $6;
    sentence = "";
    command = "";
    foundCommand = 0;
    sentence = user " used sudo to do \`";
    for(i = 1; i <= NF; i++) {
        if (foundCommand == 0) {
            if ($i ~ /^COMMAND/) {
                foundCommand = 1;
                command = substr($i, 9);
                sentence = sentence command;
            }
        }
        else {
            sentence = sentence " " $i;
        }
    }
    if (foundCommand == 0) {
        next;
    }
    month = "";
    day = "";
    if ($1 == "Jan") {
        month = "01";
    } else if ($1 == "Feb") {
        month = "02";
    } else if ($1 == "Mar") {
        month = "03";
    } else if ($1 == "Apr") {
        month = "04";
    } else if ($1 == "May") {
        month = "05";
    } else if ($1 == "Jun") {
        month = "06";
    } else if ($1 == "Jul") {
        month = "07";
    } else if ($1 == "Aug") {
        month = "08";
    } else if ($1 == "Sep") {
        month = "09";
    } else if ($1 == "Oct") {
        month = "10";
    } else if ($1 == "Nov") {
        month = "11";
    } else if ($1 == "Dec") {
        month = "12";
    }

    if ($2 == "1") {
        day = "01";
    } else if ($2 == "2") {
        day = "02";
    } else if ($2 == "3") {
        day = "03";
    } else if ($2 == "4") {
        day = "04";
    } else if ($2 == "5") {
        day = "05";
    } else if ($2 == "6") {
        day = "06";
    } else if ($2 == "7") {
        day = "07";
    } else if ($2 == "8") {
        day = "08";
    } else if ($2 == "9") {
        day = "09";
    } else {
        day = $2;
    }
    sentence = sentence "\` on 2021-" month "-" day " " $3;
    printf("TWO:%s\n", sentence);
}
END{
    sentence = "";
    for(i = 1; i <= failedIpCnt; i++) {
        ip = failedIp[i];
        sentence = ip " failed to log in " failedCntOfIp[ip] " times";
        printf("ONE:%s\n", sentence);
    }
    sentence = "";
    for(i = 1; i <= failedUserCnt; i++) {
        user = failedUser[i];
        sentence = user " failed to log in " failedCntOfUser[user] " times";
        printf("THREE:%s\n", sentence);
    }
}' | sed -n -e 's/ONE://w audit_ip.txt' -e 's/TWO://w audit_sudo.txt' -e 's/THREE://w audit_user.txt'