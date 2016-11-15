<?php

const apkdigests = [
    'CHANGEME', // $ sha256sum app-debug.apk
];
define('EXPECTED_PACKAGE_NAME', 'com.cigital.safetynetplayground'); // packagename of the app
define('EXPECTED_APK_CERT_DIGEST', 'CHANGEME'); // sha256sum of the signature of the leaf certificate signing the app
define('EXPECTED_APK_DIGEST_LIST', apkdigests);
define('APIKEY', 'CHANGEME'); // Android Device Verification API key
