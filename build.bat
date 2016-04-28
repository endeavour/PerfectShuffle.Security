@echo off
cls

.paket\paket restore
"packages\FAKE\tools\Fake.exe" build.fsx
