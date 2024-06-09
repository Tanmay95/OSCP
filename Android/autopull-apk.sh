#!/bin/bash

APK_PATH="$(adb shell pm path $1)"
echo "${APK_PATH#*:}"

APK_PATH=${APK_PATH#*:}
adb pull $APK_PATH
mv base.apk $1.apk

if [ "$2" == "--jadx" ] || [ "$2" = "-j" ]
then

bash -/jadx/btn/jadx-gui $1
fi