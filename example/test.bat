@echo off

go build -v -trimpath -o GRT-PELoader.exe ../tool/pe_loader/main.go

go build -v -trimpath -ldflags "-s -w" -o argument.exe     argument/main.go
go build -v -trimpath -ldflags "-s -w" -o im_storage.exe   im_storage/main.go
go build -v -trimpath -ldflags "-s -w" -o sleep.exe        sleep/main.go
go build -v -trimpath -ldflags "-s -w" -o sleep_raw.exe    sleep_raw/main.go
go build -v -trimpath -ldflags "-s -w" -o metrics.exe      metrics/main.go
go build -v -trimpath -ldflags "-s -w" -o watchdog.exe     watchdog/main.go
go build -v -trimpath -ldflags "-s -w" -o raw_api.exe      raw_api/main.go
go build -v -trimpath -ldflags "-s -w" -o exit_process.exe exit_process/main.go

GRT-PELoader.exe -pe argument.exe
GRT-PELoader.exe -pe im_storage.exe
GRT-PELoader.exe -pe sleep.exe
GRT-PELoader.exe -pe sleep_raw.exe
GRT-PELoader.exe -pe metrics.exe
GRT-PELoader.exe -pe watchdog.exe
GRT-PELoader.exe -pe raw_api.exe
GRT-PELoader.exe -pe exit_process.exe

del /Q *.exe