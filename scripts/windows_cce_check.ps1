#Requires -RunAsAdministrator
###############################################################################
# Windows CCE Vulnerability Check Script
# Based on:
#   1) 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
#   2) 클라우드 취약점 점검 가이드 (2024)
#
# Usage: .\windows_cce_check.ps1 [-OutputFile <path>]
# Output: JSON file with all check results
###############################################################################

param(
    [string]$OutputFile = "cce_check_result_windows_$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
)

$ErrorActionPreference = "SilentlyContinue"

# --- JSON helper ---
$script:results = @()

function Write-ResultTrace {
    param(
        [string]$Code,
        [string]$Status,
        [string]$Title,
        [string]$Command,
        [string]$CurrentState,
        [string]$Detail
    )

    $commandText = (($Command ?? '') -replace "`r?`n", ' ').Trim()
    $stateText = (($CurrentState ?? '') -replace "`r?`n", ' ').Trim()
    $detailText = (($Detail ?? '') -replace "`r?`n", ' ').Trim()
    if (-not $commandText) { $commandText = '-' }
    if (-not $stateText) { $stateText = '-' }
    if (-not $detailText) { $detailText = '-' }

    Write-Host ""
    Write-Host "[TRACE] code=$Code status=$Status title=$Title"
    Write-Host "[TRACE] command=$commandText"
    Write-Host "[TRACE] current_state=$stateText"
    Write-Host "[TRACE] detail=$detailText"
}

function Add-Result {
    param(
        [string]$Code,
        [string]$Category,
        [string]$Title,
        [string]$Importance,
        [string]$Status,
        [string]$Detail,
        [string]$Source,
        [string]$Command,
        [string]$CurrentState,
        [string]$Remediation
    )

    $script:results += [PSCustomObject]@{
        code          = $Code
        category      = $Category
        title         = $Title
        importance    = $Importance
        status        = $Status
        detail        = $Detail
        source        = $Source
        command       = $Command
        current_state = $CurrentState
        remediation   = $Remediation
    }
    Write-ResultTrace -Code $Code -Status $Status -Title $Title -Command $Command -CurrentState $CurrentState -Detail $Detail
}

function Get-OutputSummary {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return "" }
    return (($Text -replace "`r?`n", ' ') -replace '\s+', ' ').Trim()
}

function Get-FirstNumber {
    param([string]$Text)
    $match = [regex]::Match(($Text ?? ''), '\d+')
    if ($match.Success) { return [int]$match.Value }
    return $null
}

function Test-NegativeMarker {
    param([string]$Text)
    return [regex]::IsMatch(($Text ?? ''), '(^|[^A-Za-z0-9_-])(0|false|off|disabled|inactive|none|no|deny|never)([^A-Za-z0-9_-]|$)|계정 사용 안함|사용 안함|비활성', 'IgnoreCase')
}

function Test-PositiveMarker {
    param([string]$Text)
    return [regex]::IsMatch(($Text ?? ''), '(^|[^A-Za-z0-9_-])(1|true|on|enabled|enable|active|yes|allow)([^A-Za-z0-9_-]|$)|활성', 'IgnoreCase')
}


# CSAP-Windows-01 / ISMS-W-01: Administrator 계정 이름 바꾸기
function Check-CSAP_Windows_01 {
    $status = "양호"
    $detail = ""
    $cmd = "net user"
    $curState = ""
    $remediation = "[클라우드 가이드] [CLI] ￭ 명령 프롬프트에서 변경 시작 → 실행 → cmd → wmic UserAccount where Name=`"administrator`" call Rename Name=`"변경할 계정명`" 명령어 입력 ※ cmd를 관리자 권한으로 실행 [GUI] ￭ 로컬 보안 정책에서 변경 시작 → 프로그램 → 관리도구 → 로컬 보안 정책 → 로컬 정책 → 보안 옵션 → `"계정: Administrator 계정 이름 바꾸기`"에서 계정 이름 변경 [주요기반시설 가이드] Administrator 기본 계정 이름 변경 및 보안성이 있는 비밀번호 설정 [상세 조치 사례] l Windows NT, 2000, 2003, 2008, 2012, 2016, 2019, 2022 Step 1) 시작 ＞ 제어판 > 관리 도구 > 관리 보안 정책 > 로컬 정책 > 보안 옵션 Step 2) “계정: Administrator 계정 이름 바꾸기”를 유추하기 어려운 계정 이름으로 변경 [ Administrator 계정 이름 변경 ] 178"

    try {
        $output = net user Administrator 2>$null | Out-String
        $curState = $output.Trim()
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($curState)) {
            $status = "취약"
            $detail = "Administrator 기본 계정 이름을 변경하지 않거나 단순 비밀번호를 적용한 경우"
        } else {
            $status = "양호"
            $detail = "Administrator 기본 계정 이름을 변경하거나 강화된 비밀번호를 적용한 경우"
            if ([string]::IsNullOrWhiteSpace($curState)) { $curState = "Administrator 기본 이름 미확인" }
        }
    } catch {
        $curState = "net user 실행 실패"
        $detail = "계정 조회 실패."
        $status = "N/A"
    }

    Add-Result -Code "CSAP-Windows-01 / ISMS-W-01" -Category "보안 관리" -Title "Administrator 계정 이름 바꾸기" `
        -Importance "상" -Status $status -Detail $detail `
        -Source "통합" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# CSAP-Windows-02 / ISMS-W-02: Guest 계정 상태
function Check-CSAP_Windows_02 {
    $status = "양호"
    $detail = ""
    $cmd = "net user guest"
    $curState = ""
    $remediation = "[클라우드 가이드] [CLI] ￭ 명령 프롬프트에서 변경 시작 → 실행 → cmd → net user guest /active:no 명령어 실행 ※ cmd를 관리자 권한으로 실행 [GUI] ￭ 로컬 보안 정책에서 변경 시작 → 프로그램 → 관리도구 → 로컬 보안 정책 → 로컬 정책 → 보안 옵션 → “계정: Guest 계정 상태 속성”에서 “사용 안 함” [주요기반시설 가이드] Guest 계정 비활성화 [상세 조치 사례] l Windows NT Step 1) 시작 > 프로그램 > 관리 도구 > 도메인 사용자 관리 > Guest 계정 선택 > 등록정보 Step 2) “계정 사용 안 함” 설정 l Windows 2000, 2003, 2008, 2012, 2016, 2019, 2022 Step 1) 시작 > 제어판 > 관리 도구 > 로컬 보안 정책 > 로컬 정책 > 보안 옵션 > 계정: Guest 계정 상태 Step 2) 계정 “사용 안 함” 설정 [ Guest 계정 상태 사용 안 함 설정 ] 02. Windows 서버 179"

    try {
        $output = net user Guest 2>$null | Out-String
        $curState = $output.Trim()
        if ([string]::IsNullOrWhiteSpace($curState)) {
            $status = "N/A"
            $detail = "Guest 계정 정보를 조회하지 못했습니다."
        } elseif ($curState -match "Account active\s+Yes|활성 계정\s+예|계정 활성\s+예") {
            $status = "취약"
            $detail = "Guest 계정이 활성화되어 있는 경우"
        } elseif ($curState -match "Account active\s+No|활성 계정\s+아니오|계정 활성\s+아니오|계정 사용 안함") {
            $status = "양호"
            $detail = "Guest 계정이 비활성화되어 있는 경우"
        } else {
            $status = "수동점검"
            $detail = "Guest 계정 상태 해석에 추가 확인이 필요합니다."
        }
    } catch {
        $curState = "net user 실행 실패"
        $detail = "계정 조회 실패."
        $status = "N/A"
    }

    Add-Result -Code "CSAP-Windows-02 / ISMS-W-02" -Category "계정 관리" -Title "Guest 계정 상태" `
        -Importance "상" -Status $status -Detail $detail `
        -Source "통합" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# CSAP-Windows-03 / ISMS-W-03: 불필요한 계정 제거
function Check-CSAP_Windows_03 {
    $status = "양호"
    $detail = ""
    $cmd = "net user"
    $curState = ""
    $remediation = "[클라우드 가이드] [CLI] ￭ 명령 프롬프트에서 변경 시작 → 실행 → cmd → net user `"제거할 계정명`" /delete를 입력하여 삭제 ※ cmd를 관리자 권한으로 실행 [GUI] ￭ 로컬 보안 정책에서 변경 시작 → 프로그램 → 관리도구 → 컴퓨터 관리 → 로컬 사용자 및 그룹 → 사용자 → 속성 → `"계정 사용 안 함`"에 체크 하거나 계정 삭제 ※ 불필요한 계정은 삭제하는 것을 권고함 [주요기반시설 가이드] 현재 계정 현황 확인 후 불필요한 계정 삭제 [상세 조치 사례] l Windows NT Step 1) 시작 > 프로그램 > 관리 도구 > 도메인 사용자 관리> 계정 선택> 등록 정보 Step 2) “계정 사용 안 함” 설정 또는 계정 삭제 l Windows 2000, 2003, 2008, 2012, 2016, 2019, 2022 Step 1) 시작 > 제어판 > 관리 도구 > 컴퓨터 관리 > 로컬 사용자 및 그룹 > 사용자 Step 2) 등록된 계정 중 불필요한 사용자 선택 > 속성 > “계정 사용 안 함” 설정 또는 계정 삭제 [ 사용자 계정 확인 ] 180"

    try {
        $output = net user 2>$null
        $curState = ($output | Out-String).Trim()
        $detail = "사용자 계정 목록 확인됨. 수동 검증 필요."
        $status = "수동점검"
    } catch {
        $curState = "net user 실행 실패"
        $detail = "계정 조회 실패."
        $status = "N/A"
    }

    Add-Result -Code "CSAP-Windows-03 / ISMS-W-03" -Category "계정 관리" -Title "불필요한 계정 제거" `
        -Importance "상" -Status $status -Detail $detail `
        -Source "통합" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# CSAP-Windows-04 / ISMS-W-04: 계정 잠금 임계값 설정
function Check-CSAP_Windows_04 {
    $status = "양호"
    $detail = ""
    $cmd = "net accounts"
    $curState = ""
    $remediation = "[클라우드 가이드] [CLI] ￭ 명령 프롬프트에서 변경 시작 → 실행 → cmd → net accounts /lockoutthreshold:5 명령어 실행 ※ cmd를 관리자 권한으로 실행 [GUI] ￭ 로컬 보안 정책에서 변경 시작 → 프로그램 → 관리도구 → 로컬 보안 정책 → 계정 정책 → 계정 잠금 정책 → `"계정 잠금 임계값`"을 5번 이하로 설정 [주요기반시설 가이드] 계정 잠금 임계값을 5 이하의 값으로 설정 [상세 조치 사례] l Window NT Step 1) 시작 > 프로그램 > 관리 도구 > 도메인 사용자 관리자 > 정책 > 계정 정책 Step 2) “계정 잠금” 선택 후 “잠금”에 “5” 이하의 값 설정 l Windows 2000, 2003, 2008, 2012, 2016, 2019, 2022 Step 1) 시작 > 제어판 > 관리 도구 > 로컬 보안 정책 > 계정 정책 > 계정 잠금 정책 Step 2) “계정 잠금 임계값”을 “5” 이하의 값으로 설정 [ 계정 잠금 임계값 설정 ] 02. Windows 서버 181"

    try {
        $output = net accounts 2>$null | Out-String
        $curState = $output.Trim()
        $thresholdLine = ($output -split "`r?`n" | Where-Object { $_ -match "Lockout threshold|잠금 임계값" } | Select-Object -First 1)
        $numericValue = Get-FirstNumber $thresholdLine
        if ($null -eq $numericValue -or $numericValue -eq 0) {
            $status = "취약"
            $detail = "계정 잠금 임계값이 5 초과의 값으로 설정된 경우"
        } elseif ($numericValue -le 5) {
            $status = "양호"
            $detail = "계정 잠금 임계값이 5 이하의 값으로 설정된 경우"
        } else {
            $status = "취약"
            $detail = "계정 잠금 임계값이 5 초과의 값으로 설정된 경우"
        }
    } catch {
        $curState = "net user 실행 실패"
        $detail = "계정 조회 실패."
        $status = "N/A"
    }

    Add-Result -Code "CSAP-Windows-04 / ISMS-W-04" -Category "계정 관리" -Title "계정 잠금 임계값 설정" `
        -Importance "상" -Status $status -Detail $detail `
        -Source "통합" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# CSAP-Windows-07 / ISMS-W-05: 해독 가능한 암호화를 사용하여 암호 저장
function Check-CSAP_Windows_07 {
    $status = "양호"
    $detail = ""
    $cmd = "secedit /export /cfg c:\cfg.txt"
    $curState = ""
    $remediation = "[클라우드 가이드] [CLI] ￭ 명령 프롬프트에서 변경 1. 탐색기 → cfg.txt 파일을 열어서 ClearTextPassword 설정 값을 0으로 변경 2. 시작 → 실행 → cmd.exe → secedit /configure /db C:\cfg.sdb /cfg C:\cfg.txt 명령어 실행 ※ cmd를 관리자 권한으로 실행 [GUI] ￭ 로컬 보안 정책에서 변경 시작 → 프로그램 → 관리도구 → 로컬 보안 정책 → 계정 정책 → 암호 정책 → `"해독 가능한 암호화를 사용하여 암호 저장`"을 `"사용 안 함`"으로 설정 [주요기반시설 가이드] “해독 가능한 암호화를 사용하여 암호 저장”을 “사용 안 함”으로 설정 [상세 조치 사례] l Window NT, 2000, 2003, 2008, 2012, 2016, 2019, 2022 Step 1) 시작 > 제어판 > 관리 도구 > 로컬 보안 정책 > 계정 정책 > 암호 정책 Step 2) “해독 가능한 암호화를 사용하여 암호 저장”을 “사용 안 함”으로 설정 [ 해독 가능한 암호화를 사용하여 암호 저장 정책 설정 ] 182"

    # Export security policy
    $tempFile = "$env:TEMP\secedit_export.cfg"
    secedit /export /cfg $tempFile 2>$null | Out-Null
    if (Test-Path $tempFile) {
        $content = Get-Content $tempFile | Select-String "ClearTextPassword"
        if ($content) {
            $curState = $content.ToString().Trim()
            $numericValue = Get-FirstNumber $curState
            if ($numericValue -eq 0) {
                $status = "양호"
                $detail = "“해독 가능한 암호화를 사용하여 암호 저장” 정책이 “사용 안 함”으로 설정된 경우"
            } else {
                $status = "취약"
                $detail = "“해독 가능한 암호화를 사용하여 암호 저장” 정책이 “사용”으로 설정된 경우"
            }
        } else {
            $curState = "ClearTextPassword 설정 미발견"
            $detail = "보안정책 ClearTextPassword 미설정."
            $status = "취약"
        }
        Remove-Item $tempFile -Force 2>$null
    } else {
        $curState = "secedit 내보내기 실패"
        $detail = "보안정책 내보내기 실패."
        $status = "N/A"
    }

    Add-Result -Code "CSAP-Windows-07 / ISMS-W-05" -Category "계정 관리" -Title "해독 가능한 암호화를 사용하여 암호 저장" `
        -Importance "상" -Status $status -Detail $detail `
        -Source "통합" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# CSAP-Windows-08 / ISMS-W-06: 관리자 그룹에 최소한의 사용자 포함
function Check-CSAP_Windows_08 {
    $status = "양호"
    $detail = ""
    $cmd = "net localgroup administrators"
    $curState = ""
    $remediation = "[클라우드 가이드] [CLI] ￭ 명령 프롬프트에서 변경 시작 → 실행 → cmd → net localgroup administrators 삭제할 계정명 /del 명령어 입력 ※ cmd를 관리자 권한으로 실행 [GUI] ￭ 컴퓨터 관리에서 변경 시작 → 프로그램 → 관리도구 → 컴퓨터 관리 → 로컬 사용자 및 그룹 → 그룹 → Administrators 선택 → 불필요한 계정 제거 [주요기반시설 가이드] Administrators 그룹에 포함된 불필요한 계정 제거 [상세 조치 사례] l Window NT Step 1) 시작 > 프로그램 > 관리 도구 > 도메인 사용자 관리 > Administrators 그룹 > 등록 정보 Step 2) Administrator 그룹에서 불필요한 계정 제거 후 그룹 변경 02. Windows 서버 l Windows 2000, 2003, 2008, 2012, 2016, 2019, 2022 Step 1) 시작 > 제어판 > 관리 도구 > 컴퓨터 관리 > 로컬 사용자 및 그룹 > 그룹 > Administrators > 속성 Step 2) Administrators 그룹에서 불필요한 계정 제거 후 그룹 변경 [ 관리자 계정 그룹 불필요한 계정 확인 ] 184"

    try {
        $output = net user Administrator 2>$null | Out-String
        $curState = $output.Trim()
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($curState)) {
            $status = "취약"
            $detail = "Administrators 그룹에 불필요한 관리자 계정이 존재하는 경우"
        } else {
            $status = "양호"
            $detail = "Administrators 그룹의 구성원을 1명 이하로 유지하거나, 불필요한 관리자 계정이 존재하지 않"
            if ([string]::IsNullOrWhiteSpace($curState)) { $curState = "Administrator 기본 이름 미확인" }
        }
    } catch {
        $curState = "net user 실행 실패"
        $detail = "계정 조회 실패."
        $status = "N/A"
    }

    Add-Result -Code "CSAP-Windows-08 / ISMS-W-06" -Category "계정 관리" -Title "관리자 그룹에 최소한의 사용자 포함" `
        -Importance "상" -Status $status -Detail $detail `
        -Source "통합" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# CSAP-Windows-09 / ISMS-W-16: 공유 권한 및 사용자 그룹 설정
function Check-CSAP_Windows_09 {
    $status = "양호"
    $detail = ""
    $cmd = "net share"
    $curState = ""
    $remediation = "[클라우드 가이드] [CLI] ￭ 명령 프롬프트에서 변경 1. 시작 → 실행 → cmd → net share 공유이름 /delete 명령어 입력 2. cmd → net share 공유이름 = 드라이브 경로 /grant:계정명,권한 명령어 입력 ※ 권한의 종류는 READ(읽기), CHANGE(변경), FULL(읽기 및 변경)으로 권한에 따라 적절히 적용 ※ 적용할 계정이 여러개 있을 시 /grant:계정명,권한을 여러개 붙여서 사용 EX) net share test=C:\test /grant:test1,read /grant:test2,full ※ cmd를 관리자 권한으로 실행 [GUI] ￭ 컴퓨터 관리에서 변경 시작 → 프로그램 → 관리도구 → 컴퓨터 관리 → 공유 폴더 → 공유 → 일반 공유 폴더 선택 → 속성 → 공유 사용 권한 탭에서 Everyone으로 된 공유를 제거하고, 접근이 필요한 계정의 권한만 추가 [주요기반시설 가이드] 공유 디렉터리 접근 권한에서 Everyone 권한 제거 후 필요한 계정 추가 [상세 조치 사례] l Windows NT Step 1) 프로그램 > 관리 도구 > 서버 관리자 > 컴퓨터 > 공유 디렉터리 > 등록 정보 > 사용 권한에서 Everyone 으로 설정된 공유를 제거하고 접근이 필요한 계정에 적절한 권한 추가 l Windows 2000, 2003, 2008, 2012, 2016, 2019, 2022 Step 1) 시작 > 실행 > FSMGMT.MSC > 공유 Step 2) 사용 권한에서 Everyone으로 된 공유를 제거하고 접근이 필요한 계정의 적절한 권한 추가 [ 공유 폴더 사용 권한 설정 ] 198"

    try {
        $output = net user 2>$null
        $curState = ($output | Out-String).Trim()
        $detail = "사용자 계정 목록 확인됨. 수동 검증 필요."
        $status = "수동점검"
    } catch {
        $curState = "net user 실행 실패"
        $detail = "계정 조회 실패."
        $status = "N/A"
    }

    Add-Result -Code "CSAP-Windows-09 / ISMS-W-16" -Category "서비스 관리" -Title "공유 권한 및 사용자 그룹 설정" `
        -Importance "상" -Status $status -Detail $detail `
        -Source "통합" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# CSAP-Windows-10 / ISMS-W-17: 하드디스크 기본 공유 제거
function Check-CSAP_Windows_10 {
    $status = "양호"
    $detail = ""
    $cmd = "net share"
    $curState = ""
    $remediation = "[클라우드 가이드] [CLI] ￭ 명령 프롬프트에서 변경 시작 → 실행 → cmd → net share 삭제할 공유 이름 /del 명령어 실행 ※ cmd를 관리자 권한으로 실행 ※ cmd에서 설정을 변경할 경우 프로그램 재시작 후 기본공유가 다시 생성되므로 영구적인 제거가 불가능함 [GUI] ￭ 컴퓨터 관리에서 변경 시작 → 프로그램 → 관리도구 → 컴퓨터 관리 → 공유 폴더 → ‘공유’에서 불필요한 기본공유에 대해 `"공유 중지`" 설정 [레지스트리] ￭ 레지스트리에서 변경 시작 → 실행 → regedit → HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lanmanserver\ parameters 에서 AutoShareServer 의 값을 0으로 수정 (AutoShareServer 설정이 존재하지 않을 경우 DWORD로 새로 만들기) ※ 레지스트리 값을 수정해야만 영구적인 기본공유 중지 적용이 가능함 ※ IPC`$는 중지할 경우, 네트워크 서비스에 문제가 발생할 가능성이 존재하므로 제거를 권고하지 않음 ※ IPC`$를 제외한 나머지 기본공유는 제거해야 함 [주요기반시설 가이드] 기본 공유 중지 후 레지스트리 값 설정(IPC`$, 일반 공유 제외) [상세 조치 사례] l Windows NT Step 1) 프로그램 > 관리도구 > 서버 관리자 > 컴퓨터 > 공유 디렉터리 > 공유 > 공유 중지 02. Windows 서버 l Windows 2000, 2003, 2008, 2012, 2016, 2019, 2022 Step 1) 시작 > 실행 > FSMGMT.MSC > 공유 > 기본 공유(Default share) 선택 > 마우스 우클릭 > 공유 중지 [ 기본 공유 폴더 중지 설정 ] Step 2) 시작 > 제어판 > 관리 도구 > 레지스트리 편집기 아래 레지스트리 값을 0으로 수정(키 값이 없을 경우 새로 생성) “HKLM\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters\” Step 3) AutoShareServer(Windows NT: AutoShareWks)을 “0”으로 수정 [ AutoShareServer 값 설정 ] ※ 방화벽과 라우터에서 135~139(TCP/UDP) Port를 차단하여 외부로부터의 위험을 제거함으로써 보안성을 높 일 수 있음 200"

    try {
        $output = net user 2>$null
        $curState = ($output | Out-String).Trim()
        $detail = "사용자 계정 목록 확인됨. 수동 검증 필요."
        $status = "수동점검"
    } catch {
        $curState = "net user 실행 실패"
        $detail = "계정 조회 실패."
        $status = "N/A"
    }

    Add-Result -Code "CSAP-Windows-10 / ISMS-W-17" -Category "서비스 관리" -Title "하드디스크 기본 공유 제거" `
        -Importance "상" -Status $status -Detail $detail `
        -Source "통합" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# CSAP-Windows-11 / ISMS-W-18: 불필요한 서비스 제거
function Check-CSAP_Windows_11 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "[클라우드 가이드] [CLI] ￭ 명령 프롬프트에서 변경 1. 시작 → 실행 → cmd → net stop 서비스명 명령어 실행 2. cmd → sc config 서비스명 start= disabled 명령어 실행 ※ cmd를 관리자 권한으로 실행 [GUI] ￭ 컴퓨터 관리에서 변경 1. 시작 → 관리도구 → 서비스 → 해당 서비스 더블 클릭 2. 일반 → 시작 유형 → “사용 안 함”으로 설정 [주요기반시설 가이드] 서비스 중지 후 “사용 안 함” 설정 [상세 조치 사례] l Windows NT Step 1) 시작 > 설정 > 제어판 > 서비스를 선택하여 불필요한 서비스를 중지하고, 시작 옵션에서 `"시작 유형`"을 `" 사용 안 함`"으로 수정 Step 2) 해당 서비스를 선택하고 오른쪽 메뉴에서 `"시작 옵션`"을 클릭하면 시스템이 시작할 때에 해당 서비스의 시작 유형을 선택할 수 있음. 만약, 시스템 시작 시 자동으로 시작되게 하려면 [자동], 수동으로 서비스를 시작하려면 [수동], 서비스 자체를 사용하지 않으려면 [사용 안 함]을 선택한 후 [확인]을 클릭함 02. Windows 서버 l Windows 2000, 2003, 2008, 2012, 2016, 2019, 2022 Step 1) 시작 > 제어판 > 서비스 > `"해당 서비스`" 선택 > 속성 Step 2) 시작 유형 - > 사용 안 함 Step 3) 서비스 상태 - > 중지 설정 [ 불필요한 서비스 중지 설정 ] ※ 특별한 목적을 위해 사용하는 서비스가 아니라면 시스템의 업무에 부합되는 서비스가 아닌 기타 기본 서비스 를 사용하지 않는 것을 권고하며, 시스템 관리자는 대상 시스템의 용도를 정확히 파악해 불필요한 서비스를 제거해야 함 서비스 시작 유형 설명 사용 안 함 설치되어 있으나 실행되지 않음 수동 다른 서비스나 응용 프로그램에서 해당 기능을 필요로 할 때만 시작됨 자동 부팅 시에 해당 장치 드라이버가 로드된 후에 운영체제에 의해 시작됨 ※ 각 서비스마다 옵션을 설정할 수 있으며 해당 서비스의 시작 유형을 선택할 수 있으며 시작 시 로그온 계정을 별도로 설정할 수 있음. 만약, 시스템 시작 시 자동으로 시작되게 하려면 [자동], 수동으로 서비스를 시작하려 면 [수동], 서비스 자체를 사용하지 않으려면 [사용 안 함]을 선택 ※ 일반적으로 불필요한 서비스 서비스명 기능 및 설명 Alerter 네트워크상에서 사용자와 컴퓨터에 관리용 경고 메시지를 전송하는 기능 Automatic Updates 중요한 윈도우 업데이트를 다운로드하고 설치할 수 있도록 하는 응용프로그램. 수동 패치를 적용하거나, MS 패치 관리 서버로 패치를 일괄적으로 관리하는 경우 불필요한 서비스 Clipbook 서버 내 Clipbook을 다른 클라이언트와 공유 Computer Browser 네트워크에 있는 모든 컴퓨터의 목록을 업데이트하고 관리하는 기능 Cryptographic Services 윈도우 파일의 서명을 확인하는 카탈로그 데이터베이스 서비스를 총괄 DHCP Client IP주소와 DNS 이름을 DHCP 서버에 등록하거나 DHCP 서버로부터 동적으로 IP주소를 가져오는 기능을 수행. 단독으로 시스템을 수행하며 고정 IP를 사용하는 경우 불필요한 서비스 Distributed Link Tracking Client, Server 네트워크 도메인의 여러 컴퓨터나 일반 컴퓨터에서 NTFS 파일간의 연결을 관리하는 도구. Active Directory가 구성되어 있지 않은 서버에서는 불필요한 서비스 DNS Client 컴퓨터에 대한 도메인 이름 시스템(DNS) 이름을 확인하고 캐시에 보관하는 기능. DNS 서버가 아닌 시스템에서는 유명무실하나, IPSEC을 사용하는 경우에는 필요할 수 있음 Error reporting Service 프로그램 오류가 발생 시 응용프로그램의 오류를 MS에 보고한다는 내용을 표시하는 기능 Human Interface Device Access 키보드 또는 기타 멀티미디어 장치에 사전 정의된 버튼들을 사용하는 HID 장치들을 위한 서비스 IMAPI CD-Burning COM Service 서버에 CD-RW 또는 DVD-RW가 장착되어 보조백업장치 역할을 하기 위해서 자체 레코딩 백업을 할 수 있음 Infrared Monitor 사용자 적외선 연결을 통해 파일 및 이미지를 공유할 수 있도록 함 Messenger 클라이언트와 서버 사이에 netsend 및 경고서비스 메시지를 전송하는 기능 NetMeeting Remote Desktop Sharing 윈도우9X 운영체제부터 인증된 사용자가 넷미팅을 사용해서 원격으로 컴퓨터에 접근할 수 있도록 하는 기능 Portable Media Serial Number 컴퓨터에 연결된 이동성 음악 연주기(미디어기기)의 등록번호를 복원하는 기능 Print Spooler 인쇄 과정에 있는 스풀링을 관리하는 서비스. 프린터가 있는 경우 필수 서비스이지만, 프린터가 연결되지 않은 시스템에서는 불필요함 Remote Registry 원격 사용자가 이 컴퓨터에서 레지스트리 설정을 수정할 수 있도록 설정하는 응용프로그램 Simple TCP/IP Services Echo, Discard, Character Generator, Daytime, Quote of the Day 지원 02. Windows 서버 ※ 운영 중인 시스템에서 필수 서비스를 정의하는 것은 매우 복잡한 과정으로 서비스 사용 여부는 시스템의 영 향성을 고려하여 신중하게 평가되어야 하므로 Microsoft에서 권고하는 가이드에 따라 전략적으로 적용해야 함 ※ https://technet.microsoft.com/ko-kr/library/dd547941.aspx (서비스 및 서비스 계정 보안 계획 가이드) 참고 ※ 윈도우 시스템 설치 시 기본적으로 설치되는 서비스에 대한 상세 설명은 아래 주소 참조 https://technet.microsoft.com/ko-kr/library/dd547949.aspx 서비스명 기능 및 설명 Universal Plug and Play Device Host 네트워크 장치에 대해 피어-투-피어 UPnP(범용 플러그 앤 플레이) 기능을 지원 Wireless Zero Configuration 802.11 어댑터에 대해 자동 구성을 공급하는 기본적인 도구 204"

    $status = "수동점검"
    $detail = "서비스 상태 수동 확인 필요. 일반적으로 불필요한 서비스(아래 목록 참조)가 중지된 경우"
    $curState = "수동점검 필요"

    Add-Result -Code "CSAP-Windows-11 / ISMS-W-18" -Category "서비스 관리" -Title "불필요한 서비스 제거" `
        -Importance "상" -Status $status -Detail $detail `
        -Source "통합" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# CSAP-Windows-12 / ISMS-W-20: NetBIOS 바인딩 서비스 구동 점검
function Check-CSAP_Windows_12 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "[클라우드 가이드] [레지스트리] ￭ 레지스트리에서 변경 시작 → 실행 → regedit → HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\NetBT\Parame ters\Interfaces에서 NetbiosOptions 데이터 값을 2로 변경 [GUI] ￭ 네트워크 및 공유 센터에서 변경 시작 → 제어판 → 네트워크 및 공유 센터 → 어댑터 설정 변경 → 해당 네트워크 어댑터 선택 후 마우스 오른쪽 버튼을 클릭하여 “속성” 선택 → 목록에서 `"Internet Protocol Version 4 (TCP/IPv4)`" 또는 `"Internet Protocol Version 6 (TCP/IPv6)`"를 찾아 선택한 다음 `"속성`" 선택 → 속성 창에서 “고급” 선택 → “WINS” 탭에서 NetBIOS 설정을 “사용 안 함”으로 변경 [주요기반시설 가이드] 네트워크 제어판을 이용하여 TCP/IP와 NetBIOS 간의 바인딩(binding) 제거 [상세 조치 사례] l Windows NT, 2000, 2003, 2008, 2012, 2016, 2019, 2022 Step 1) 시작 > 제어판 > 네트워크 및 공유 센터 > 어댑터 설정 변경 > 로컬 영역 연결 > 속성 > TCP/IP > [일반] 탭에서 [고급] 클릭 Step 2) [WINS] 탭에서 TCP/IP에서 “NetBIOS 사용 안 함” 또는, “NetBIOS over TCP/IP 사용 안 함” 선택 [ NetBIOS 사용 안 함 설정 ] 02. Windows 서버 207"

    try {
        $curState = "레지스트리 경로 미지정"
        $detail = "수동 점검 필요. TCP/IP와 NetBIOS 간의 바인딩이 제거되어 있는 경우"
        $status = "수동점검"
    } catch {
        $curState = "레지스트리 조회 실패: $_"
        $detail = "레지스트리 키 미존재 또는 접근 불가."
        $status = "수동점검"
    }

    Add-Result -Code "CSAP-Windows-12 / ISMS-W-20" -Category "서비스 관리" -Title "NetBIOS 바인딩 서비스 구동 점검" `
        -Importance "상" -Status $status -Detail $detail `
        -Source "통합" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# CSAP-Windows-14 / ISMS-W-22: FTP 디렉터리 접근 권한 설정
function Check-CSAP_Windows_14 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "[클라우드 가이드] [GUI] ￭ 인터넷 정보 서비스(IIS) 관리에서 변경 1. 시작 → 프로그램 → 관리도구 → 인터넷 정보 서비스(IIS) 관리 → FTP 사이트 → 해당 FTP 사이트 → 기본 설정에서 FTP 홈 디렉터리 확인 2. 탐색기 → 홈 디렉터리 → 속성 → [보안] 탭에서 Everyone 권한 제거 [주요기반시설 가이드] FTP 홈 디렉터리에서 Everyone 권한 삭제, 각 사용자에게 적절한 권한 부여 [상세 조치 사례] l Windows NT(IIS 4.0), 2000(IIS 5.0), 2003(IIS 6.0) Step 1) 인터넷 정보 서비스(IIS) 관리 > FTP 사이트 > 해당 FTP 사이트 > 속성 > [홈 디렉터리] 탭에서 FTP 홈 디렉터리 확인 Step 2) 탐색기 > 홈 디렉터리 > 속성 > [보안] 탭에서 Everyone 권한 제거 02. Windows 서버 l Windows 2008(IIS 7.0), 2012(IIS 8.0), 2016, 2019, 2022(IIS 10.0) Step 1) 제어판 > 관리 도구 > 인터넷 정보 서비스(IIS) 관리 > 사이트 > 해당 FTP 사이트 > FTP 권한 부여 규칙 선택 Step 2) 허용 권한 부여 규칙에서 “지정한 사용자” 지정 [ FTP 권한 부여 규칙 ] [ 지정한 사용자 설정 ] 210"

    $status = "수동점검"
    $detail = "서비스 상태 수동 확인 필요. FTP 홈 디렉터리에 Everyone 권한이 없는 경우"
    $curState = "수동점검 필요"

    Add-Result -Code "CSAP-Windows-14 / ISMS-W-22" -Category "서비스 관리" -Title "FTP 디렉터리 접근 권한 설정" `
        -Importance "상" -Status $status -Detail $detail `
        -Source "통합" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# CSAP-Windows-16 / ISMS-W-24: FTP 접근 제어 설정
function Check-CSAP_Windows_16 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "[클라우드 가이드] ￭ 인터넷 정보 서비스(IIS) 관리에서 변경 시작 → 프로그램 → 관리도구 → IIS(인터넷 정보 서비스) 관리자 → 사용중인 FTP 서비스 → FTP IP 주소 및 도메인 제한에서 허용 및 거부 IP를 추가하여 설정 [주요기반시설 가이드] 특정 IP주소에서만 FTP 서버에 접속하도록 접근 제어 설정 [상세 조치 사례] l Windows NT(IIS 4.0), 2000(IIS 5.0), 2003(IIS 6.0) Step 1) 인터넷 정보 서비스(IIS) 관리 > FTP 사이트 > 속성 > [디렉터리 보안] 탭에서 “액세스 거부” 선택 후 접 근 가능 IP주소 추가 (만약 개별 FTP 사이트에 적용할 경우 해당 사이트에만 설정이 적용되고, 기본 설정 은 적용받지 않음) ※ 액세스 허가: 모든 액세스를 허용 후 액세스를 거부할 컴퓨터, 그룹, 도메인 추가 액세스 거부: 모든 액세스를 거부 후 액세스를 허용할 컴퓨터, 그룹, 도메인 추가 02. Windows 서버 l Windows 2008(IIS 7.0), 2012(IIS 8.0), 2016, 2019, 2022(IIS 10.0) Step 1) 제어판 > 관리 도구 > 인터넷 정보 서비스(IIS) 관리 > 해당 FTP 사이트 > FTP IPv4 주소 및 도메인 제한 Step 2) [작업]의 허용 항목 추가에서 FTP 접속을 허용할 IP 입력 Step 3) [작업]의 기능 설정 편집에서 지정되지 않은 클라이언트에 대한 액세스를 거부 선택 [ FTP IP주소 및 도메인 제한 설정 ] [ 허용 IP주소 설정 ] 214"

    $status = "수동점검"
    $detail = "서비스 상태 수동 확인 필요. 특정 IP주소에서만 FTP 서버에 접속하도록 접근 제어 설정을 적용한 경우"
    $curState = "수동점검 필요"

    Add-Result -Code "CSAP-Windows-16 / ISMS-W-24" -Category "서비스 관리" -Title "FTP 접근 제어 설정" `
        -Importance "상" -Status $status -Detail $detail `
        -Source "통합" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# CSAP-Windows-17 / ISMS-W-25: DNS Zone Transfer 설정
function Check-CSAP_Windows_17 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "[클라우드 가이드] [GUI] ￭ DNS 관리자에서 설정 시작 → 프로그램 → 관리도구 → DNS → 정방향 조회 영역 → 사용중인 DNS → 속성 → 영역 전송 에서 `"영역 전송 허용`"을 제한하거나, 사용 시 특정 서버로만 영역 전송이 이루어지도록 IP 등록 [주요기반시설 가이드] 불필요 시 서비스 중지/사용 안 함 설정, 사용하는 경우 영역 전송을 특정 서버로 제한하거나 “영역 전송 허용”에 체크 해제 [상세 조치 사례] l Windows NT Step 1) 시작 > 프로그램 > 관리 도구 > DNS 관리자 > 각 조회 영역 > 해당 영역 > 등록 정보 >알림 Step 2) “알림 목록에 있는 보조 영역에서만 액세스 허용” 선택 후 서버 IP 추가 02. Windows 서버 l Windows 2000, 2003, 2008, 2012, 2016, 2019, 2022 Step 1) 시작 > 제어판 > 관리 도구 > DNS > 각 조회 영역 > 해당 영역 > 속성 > 영역 전송 Step 2) “다음 서버로만” 선택 후 전송할 서버 IP 추가 [ 영역 전송 IP주소 지정 ] Step 3) 불필요 시 해당 서비스 중지 시작 > 실행 > SERVICES.MSC > DNS 서버 > 속성 [일반] 탭에서 “시작 유형”을 “사용 안 함”으로 설정 한 후, DNS 서비스 중지 [ DNS Server 사용 안 함 설정 ] 216"

    try {
        $curState = "레지스트리 경로 미지정"
        $detail = "수동 점검 필요. 아래 기준에 해당하는 경우"
        $status = "수동점검"
    } catch {
        $curState = "레지스트리 조회 실패: $_"
        $detail = "레지스트리 키 미존재 또는 접근 불가."
        $status = "수동점검"
    }

    Add-Result -Code "CSAP-Windows-17 / ISMS-W-25" -Category "서비스 관리" -Title "DNS Zone Transfer 설정" `
        -Importance "상" -Status $status -Detail $detail `
        -Source "통합" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# CSAP-Windows-18 / ISMS-W-26: RDS(RemoteDataServices) 제거
function Check-CSAP_Windows_18 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "[클라우드 가이드] [Win 2003] ￭ 인터넷 정보 서비스(IIS) 관리 및 레지스트리에서 변경 1. 웹 사이트로부터 “/msadc” 가상 디렉터리 제거 시작 → 실행 → INETMGR → 웹 사이트 선택 후 오른쪽 디렉터리에서 msadc 제거 2. 다음의 레지스트리 키/디렉터리 제거 HKEY_LOCAL_MACHINE \SYSTEM \CurrentControlSet \Services \W3SVC \Parameters \ADCLaunch\RDSServer.DataFactory HKEY_LOCAL_MACHINE \SYSTEM \CurrentControlSet \Services \W3SVC \Parameters \ADCLaunch\AdvancedDataFactory HKEY_LOCAL_MACHINE \SYSTEM \CurrentControlSet \Services \W3SVC \Parameters \ADCLaunch\VbBusObj.VbBusObjCls ※ Windows Server 2008 이상 버전을 사용하는 경우 양호함 [주요기반시설 가이드] 사용하지 않는 경우 IIS 서비스 중지/사용 안 함, 사용할 경우 레지스트리 키 값 제거 또는 관련 패치 적용 [상세 조치 사례] l Windows NT, 2000, 2003 Step 1) 시작 > 실행 > INETMGR > 웹 사이트 선택 후 디렉터리에서 msadc 제거 Step 2) 다음의 레지스트리 키/디렉터리 제거 HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\ADCLaunch 1. RDSServer.DataFactory 2. AdvancedDataFactory 3. VbBusObj.VbBusObjCls 02. Windows 서버 217"

    try {
        $curState = "레지스트리 경로 미지정"
        $detail = "수동 점검 필요. 다음 중 한 가지라도 해당하는 경우"
        $status = "수동점검"
    } catch {
        $curState = "레지스트리 조회 실패: $_"
        $detail = "레지스트리 키 미존재 또는 접근 불가."
        $status = "수동점검"
    }

    Add-Result -Code "CSAP-Windows-18 / ISMS-W-26" -Category "서비스 관리" -Title "RDS(RemoteDataServices) 제거" `
        -Importance "상" -Status $status -Detail $detail `
        -Source "통합" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# CSAP-Windows-20 / ISMS-W-27: 최신 Hot Fix 적용
function Check-CSAP_Windows_20 {
    $status = "양호"
    $detail = ""
    $cmd = "wmic QFE Get HotFixID,InstalledOn,Description"
    $curState = ""
    $remediation = "[클라우드 가이드] ￭ Hot Fix 수동 설치 아래의 패치 리스트를 조회하여, 서버에 필요한 패치 선별 후, 수동으로 설치 http://technet.microsoft.com/ko-kr/security/ ￭ Winodws 자동 업데이트를 통한 설치 [Win2012] 시작 → 제어판 → Windows 업데이트에서 자동 업데이트 사용을 클릭하면 자동으로 시스템에 필요한 Hot Fix 및 소프트웨어 업그레이드를 보여주고 설치를 쉽게 할 수 있다. [Win2016] 시작 → 설정 →업데이트 및 복구 → Windows 업데이트 → 업데이트 확인을 클릭하면 자동으로 시스템에 필요한 Hot Fix 및 소프트웨어 업그레이드를 보여주고 설치를 쉽게 할 수 있다 [Win2019] 시작 → 설정 → 업데이트 및 보안 → Windows 업데이트 → 업데이트 확인을 클릭하면 자동으로 시스템에 필요한 Hot Fix 및 소프트웨어 업그레이드를 보여주고 설치를 쉽게 할 수 있다 ￭ PMS(Patch Management System) Agent를 통한 설치 [Win2003, Win2008, Win2012, Win2016, Win2019] PMS Agent를 통한 보안 패치 및 Hot Fix의 경우는 적용 후 시스템 재시작을 요구하는 경우가 대부분이므로, 관리자는 서비스에 지장이 없는 시간대에 적용하는 것을 권장한다. [주요기반시설 가이드] 설치에 따른 영향도 확인 후 최신 Build 설치(설치 후 시스템 재시작 필요) [상세 조치 사례] l Windows NT, 2000, 2003, 2008, 2012, 2016, 2019, 2022 Step 1) 시작 > 실행 > Winver Step 2) Build 버전 확인 후 최신 Build 다운로드 후 설치 또는 자동업데이트 활용 ※ 인터넷 웜(Worm)이 Windows의 취약점을 이용하여 공격하기 때문에 최신 패치 설치 시에는 네트워크와 분 리된 상태에서 설치할 것을 권장 [ Windows Build 버전 확인 ] 218"

    try {
        $output = Invoke-Expression "wmic QFE Get HotFixID,InstalledOn,Description" 2>$null
        $curState = $output | Out-String
        $summary = Get-OutputSummary ($curState)
        if ([string]::IsNullOrWhiteSpace($summary)) {
            $status = "N/A"
            $detail = "명령 실행 결과 없음 또는 대상 미설치."
        } elseif (Test-NegativeMarker $summary) {
            $status = "양호"
            $detail = "최신 Build가 설치되어 있으며 적용 절차 및 방법이 수립된 경우"
        } elseif (Test-PositiveMarker $summary) {
            $status = "취약"
            $detail = "최신 Build가 설치되지 않거나, 적용 절차 및 방법이 수립되지 않은 경우"
        } else {
            $detail = "명령 실행 결과 확인. 추가 수동 검증 필요."
            $status = "수동점검"
        }
    } catch {
        $curState = "명령 실행 실패: $_"
        $detail = "점검 명령 실행 실패."
        $status = "N/A"
    }

    Add-Result -Code "CSAP-Windows-20 / ISMS-W-27" -Category "패치 및 로그 관리" -Title "최신 Hot Fix 적용" `
        -Importance "상" -Status $status -Detail $detail `
        -Source "통합" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# CSAP-Windows-21 / ISMS-W-39: 백신 프로그램 업데이트
function Check-CSAP_Windows_21 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "[클라우드 가이드] ￭ 담당자를 통해 바이러스 백신 설치 후 엔진 업데이트를 설정 백신회사 마다 다소 차이는 있으나 매주 업데이트가 이뤄지고, 긴급한 경우 수시로 업데이트를 하기도 한다. 따라서 정기적인 업데이트를 통해 검색엔진을 최신 버전으로 유지하고, 백신회사에서 발표하는 경보를 주시해야 한다. 또한, 백신 프로그램의 자동업데이트 기능을 이용하면 인터넷에 연결되어 있을 때 변동 사항을 자동으로 업데이트 되도록 설정할 수 있다. ※ 시스템 설정상, 자동업데이트 기능을 사용할 수 없는 경우, 수동으로 업데이트를 할 수 있도록 업데이트 주기 정책 설정이 필요함 [주요기반시설 가이드] 백신 프로그램 환경설정 메뉴를 통해 DB 및 엔진의 최신 업데이트를 하도록 설정 [상세 조치 사례] l Windows NT, 2000, 2003, 2008, 2012, 2016, 2019, 2022 Step 1) 긴급한 경우 수시로 업데이트 진행 (백신 프로그램 종류마다 다소 차이는 있으나 매주 업데이트가 진행됨) Step 2) 정기적인 업데이트를 통해 검색엔진을 최신 버전으로 유지하고, 백신 프로그램 제조사에서 발표하는 경보 주시 Step 3) 백신 프로그램의 자동 업데이트 기능 이용 시 온라인을 통해 변동 사항을 자동으로 업데이트하여 알 수 있음 02. Windows 서버 235"

    $status = "수동점검"
    $detail = "수동 점검 필요 항목입니다. 바이러스 백신 프로그램의 최신 엔진 업데이트가 설치되어 있거나, 망 격리 환경의 경우 백신"
    $curState = "수동점검 필요"

    Add-Result -Code "CSAP-Windows-21 / ISMS-W-39" -Category "패치 및 로그 관리" -Title "백신 프로그램 업데이트" `
        -Importance "상" -Status $status -Detail $detail `
        -Source "통합" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# CSAP-Windows-23 / ISMS-W-44: 원격으로 접근 할 수 있는 레지스트리 경로
function Check-CSAP_Windows_23 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "[클라우드 가이드] [레지스트리] ￭ 레지스트리에서 변경 시작 → 실행 → regedit → HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ RemoteRegistry 에서 Start 값을 4로 변경 [GUI] ￭ 서비스에서 변경 시작 → 프로그램 → 관리도구 → 서비스 → Remote Registry → 속성 에서 시작 유형을 `"사용 안 함`" 으로 설정하고, 서비스를 중지 [주요기반시설 가이드] 불필요 시 서비스 중지 및 사용 안 함으로 설정 [상세 조치 사례] l Windows NT, 2000, 2003, 2008, 2012, 2016, 2019, 2022 Step 1) 시작 > 제어판 > 관리 도구 > 서비스 > Remote Registry > 속성 Step 2) 시작 유형을 “사용 안 함”으로 설정한 후 서비스 중지 [ Remote Registry 사용 중지 설정 ] 점검 및 조치 사례 l Windows NT, 2000, 2003, 2008, 2012, 2016, 2019, 2022 ※ 백신 프로그램에 대한 인지도, 효과성 등을 검토하여 설치할 수 있음"

    try {
        $curState = "레지스트리 경로 미지정"
        $detail = "수동 점검 필요. Remote Registry Service가 중지된 경우"
        $status = "수동점검"
    } catch {
        $curState = "레지스트리 조회 실패: $_"
        $detail = "레지스트리 키 미존재 또는 접근 불가."
        $status = "수동점검"
    }

    Add-Result -Code "CSAP-Windows-23 / ISMS-W-44" -Category "패치 및 로그 관리" -Title "원격으로 접근 할 수 있는 레지스트리 경로" `
        -Importance "상" -Status $status -Detail $detail `
        -Source "통합" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# CSAP-Windows-24 / ISMS-W-45: 백신 프로그램 설치
function Check-CSAP_Windows_24 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "[클라우드 가이드] ￭ 담당자를 통하여 바리어스 백신을 설치하도록 권고하며, 최신 보안패치를 확인하고, 실시간 감시를 설정 - 안철수 연구소 : http://www.ahnlab.com - 하우리 : http://www.hauri.co.kr - 시만텍코리아 : http://www.symantec.co.kr - 한국트렌드마이크로: http://www.trendmicro.co.kr/ [주요기반시설 가이드] 백신 프로그램 설치"

    $status = "수동점검"
    $detail = "수동 점검 필요 항목입니다. 바이러스 백신 프로그램이 설치된 경우"
    $curState = "수동점검 필요"

    Add-Result -Code "CSAP-Windows-24 / ISMS-W-45" -Category "보안 관리" -Title "백신 프로그램 설치" `
        -Importance "상" -Status $status -Detail $detail `
        -Source "통합" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# CSAP-Windows-25 / ISMS-W-46: SAM 파일 접근 통제 설정
function Check-CSAP_Windows_25 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "[클라우드 가이드] ￭ 명령 프롬프트에서 확인 시작 → 실행 → cmd → cacls %systemroot%\system32\config\SAM /remove:g 삭제할 그룹 또는 계정명 명령어를 통해 SAM 파일 접근권한에 Administrator, System 그룹 외 나머지 계정 및 그룹 권한 제거 ￭ 탐색기에서 확인 탐색기 → C:\Windows\system32\config\SAM → 속성 → 보안 탭에서 Administrator, System 그룹 외 다른 사용자 및 그룹 권한 제거 [주요기반시설 가이드] SAM 파일 권한 확인 후 Administrator, System 그룹 외 다른 그룹에 설정된 권한 제거 [상세 조치 사례] l Windows NT, 2000, 2003, 2008, 2012, 2016, 2019, 2022 Step 1) %systemroot%\system32\config\SAM > 속성 > 보안 Step 2) Administrator, System 그룹 외 다른 사용자 및 그룹 권한 제거 [ SAM 파일 권한 확인 ] 244"

    $status = "수동점검"
    $detail = "수동 점검 필요 항목입니다. SAM 파일 접근 권한에 Administrator, System 그룹만 모든 권한으로 설정된 경우"
    $curState = "수동점검 필요"

    Add-Result -Code "CSAP-Windows-25 / ISMS-W-46" -Category "보안 관리" -Title "SAM 파일 접근 통제 설정" `
        -Importance "상" -Status $status -Detail $detail `
        -Source "통합" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# CSAP-Windows-26 / ISMS-W-48: 로그온하지 않고 시스템 종료 허용
function Check-CSAP_Windows_26 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "[클라우드 가이드] ￭ 레지스트리에서 변경 [Win2003, Win2008, Win2012, Win2016] CurrentVersion\policies\system 에서 ShutdownWithoutLogon 값이 `"0`" (사용안함) 으로 설정되어 있는지 확인 (값이 0 으로 설정되어 있는 경우 양호) ￭ 로컬 보안 정책에서 확인 시작 → 프로그램 → 관리도구 → 로컬 보안 정책 → 보안 옵션 → `" 시스템 종료: 로그인하지 않고 시스템 종료 허용” 정책을 “사용 안 함” 으로 적용 [주요기반시설 가이드] “시스템 종료: 로그온하지 않고 시스템 종료” 정책을 “사용 안 함” 설정 [상세 조치 사례] l Windows NT Step 1) 시작 > 제어판 > 관리 도구 > 레지스트리 편집기 Step 2) 다음의 레지스트리 값 추가 또는 변경 HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\ ShutdownWithoutLogon = 0 l Windows 2000 Step 1) 시작 > 실행 > SECPOL.MSC > 로컬 정책 > 보안 옵션 Step 2) “로그온하지 않고 시스템 종료 허용”을 “사용 안 함”으로 설정 02. Windows 서버 l Windows 2003, 2008, 2012, 2016, 2019, 2022 Step 1) 시작 > 제어판 > 관리 도구 > 로컬 보안 정책 > 로컬 정책 > 보안 옵션 Step 2) “시스템 종료: 로그온하지 않고 시스템 종료 허용”을 “사용 안 함”으로 설정 [ 로그온하지 않고 시스템 종료 허용 사용 안 함 설정 ] 248"

    try {
        $curState = "레지스트리 경로 미지정"
        $detail = "수동 점검 필요. “로그온하지 않고 시스템 종료 허용”이 “사용 안 함”으로 설정된 경우"
        $status = "수동점검"
    } catch {
        $curState = "레지스트리 조회 실패: $_"
        $detail = "레지스트리 키 미존재 또는 접근 불가."
        $status = "수동점검"
    }

    Add-Result -Code "CSAP-Windows-26 / ISMS-W-48" -Category "Windows 서버 > 5. 보안 관리" -Title "로그온하지 않고 시스템 종료 허용" `
        -Importance "상" -Status $status -Detail $detail `
        -Source "통합" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# CSAP-Windows-27 / ISMS-W-49: 원격 시스템에서 강제로 시스템 종료
function Check-CSAP_Windows_27 {
    $status = "양호"
    $detail = ""
    $cmd = "secedit /export /cfg c:\cfg.txt"
    $curState = ""
    $remediation = "[클라우드 가이드] ￭ 명령 프롬프트에서 변경 1. 탐색기 → cfg.txt 파일을 열어서 SeRemoteShutdownPrivilege 설정 값을 S-1-5-32-544로 변경 2. 시작 → 실행 → cmd.exe → secedit /configure /db C:\cfg.sdb /cfg C:\cfg.txt 명령어 실행 ￭ 로컬 보안 정책에서 변경 시작 → 프로그램 → 관리도구 → 로컬 보안 정책 → 로컬 정책 → 사용자 권한 할당 → “원격 시스템에서 강제 종료” 정책에 “Administrators” 그룹만 존재하도록 다른 사용자 및 그룹 제거 [주요기반시설 가이드] “원격 시스템에서 강제로 시스템 종료” 정책에 “Administrators” 외 다른 계정 및 그룹 제거 [상세 조치 사례] l Windows NT, 2000, 2003, 2008, 2012, 2016, 2019, 2022 Step 1) 시작 > 제어판 > 관리 도구 > 로컬 보안 정책 > 로컬 정책 > 사용자 권한 할당 Step 2) “원격 시스템에서 강제로 시스템 종료” 정책에 Administrators 외 다른 계정 및 그룹 제거 [ 원격 시스템에서 강제 종료 ] 02. Windows 서버 249"

    # Export security policy
    $tempFile = "$env:TEMP\secedit_export.cfg"
    secedit /export /cfg $tempFile 2>$null | Out-Null
    if (Test-Path $tempFile) {
        $content = Get-Content $tempFile | Select-String "Administrators"
        if ($content) {
            $curState = $content.ToString().Trim()
            $numericValue = Get-FirstNumber $curState
            if ($null -eq $numericValue) {
                $status = "수동점검"
                $detail = "“원격 시스템에서 강제로 시스템 종료” 정책에 “Administrators”만 존재하는 경우"
            } elseif ($numericValue -le 551) {
                $status = "양호"
                $detail = "“원격 시스템에서 강제로 시스템 종료” 정책에 “Administrators”만 존재하는 경우"
            } else {
                $status = "취약"
                $detail = "“원격 시스템에서 강제로 시스템 종료” 정책에 “Administrators” 외 다른 계정 및 그룹이 존재하"
            }
        } else {
            $curState = "Administrators 설정 미발견"
            $detail = "보안정책 Administrators 미설정."
            $status = "취약"
        }
        Remove-Item $tempFile -Force 2>$null
    } else {
        $curState = "secedit 내보내기 실패"
        $detail = "보안정책 내보내기 실패."
        $status = "N/A"
    }

    Add-Result -Code "CSAP-Windows-27 / ISMS-W-49" -Category "보안 관리" -Title "원격 시스템에서 강제로 시스템 종료" `
        -Importance "상" -Status $status -Detail $detail `
        -Source "통합" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# CSAP-Windows-28 / ISMS-W-50: 보안 감사를 로그할 수 없는 경우 시스템 종료
function Check-CSAP_Windows_28 {
    $status = "양호"
    $detail = ""
    $cmd = "secedit /export /cfg c:\cfg.txt"
    $curState = ""
    $remediation = "[클라우드 가이드] ￭ 명령 프롬프트에서 확인 1. 탐색기 → cfg.txt 파일을 열어서 CrashOnAuditFail 설정 값을 4, 0로 변경 2. 시작 → 실행 → cmd.exe → secedit /configure /db C:\cfg.sdb /cfg C:\cfg.txt 명령어 실행 ￭ 로컬 보안 정책에서 확인 시작 → 제어판 → 관리도구 → 로컬 보안 정책 → 로컬 정책 → 보안 옵션 → “감사: 보안 감사를 기록할 수 없는 경우 즉시 시스템 종료” 정책이 “사용 안함” 으로 변경 [주요기반시설 가이드] “보안 감사를 로그 할 수 없는 경우 즉시 시스템 종료” 정책을 “사용 안 함”으로 설정 [상세 조치 사례] l Windows NT, 2000 Step 1) 시작 > 실행 > SECPOL.MSC > 로컬 정책 > 보안 옵션 Step 2) “보안 감사를 로그 할 수 없는 경우 즉시 시스템 종료” 정책을 “사용 안 함”으로 설정 l Windows 2003, 2008, 2012, 2016, 2019, 2022 Step 1) 시작 > 제어판 > 관리 도구 > 로컬 보안 정책 > 로컬 정책 > 보안 옵션 Step 2) “감사: 보안 감사를 로그 할 수 없는 경우 즉시 시스템 종료” 정책을 “사용 안 함”으로 설정 [ 감사 정책 사용 안 함 설정 ] 02. Windows 서버 251"

    # Export security policy
    $tempFile = "$env:TEMP\secedit_export.cfg"
    secedit /export /cfg $tempFile 2>$null | Out-Null
    if (Test-Path $tempFile) {
        $content = Get-Content $tempFile | Select-String "CrashOnAuditFail"
        if ($content) {
            $curState = $content.ToString().Trim()
            $numericValue = Get-FirstNumber $curState
            if ($null -eq $numericValue) {
                $status = "수동점검"
                $detail = "“보안 감사를 로그 할 수 없는 경우 즉시 시스템 종료” 정책이 “사용 안 함”으로 되어있는 경우"
            } elseif ($numericValue -le 251) {
                $status = "양호"
                $detail = "“보안 감사를 로그 할 수 없는 경우 즉시 시스템 종료” 정책이 “사용 안 함”으로 되어있는 경우"
            } else {
                $status = "취약"
                $detail = "“보안 감사를 로그 할 수 없는 경우 즉시 시스템 종료” 정책이 “사용”으로 되어있는 경우"
            }
        } else {
            $curState = "CrashOnAuditFail 설정 미발견"
            $detail = "보안정책 CrashOnAuditFail 미설정."
            $status = "취약"
        }
        Remove-Item $tempFile -Force 2>$null
    } else {
        $curState = "secedit 내보내기 실패"
        $detail = "보안정책 내보내기 실패."
        $status = "N/A"
    }

    Add-Result -Code "CSAP-Windows-28 / ISMS-W-50" -Category "보안 관리" -Title "보안 감사를 로그할 수 없는 경우 시스템 종료" `
        -Importance "상" -Status $status -Detail $detail `
        -Source "통합" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# CSAP-Windows-29 / ISMS-W-51: SAM 계정과 공유의 익명 열거 허용 안함
function Check-CSAP_Windows_29 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "[클라우드 가이드] ￭ 레지스트리에서 변경 1. 시작 → 실행 → regedit 2. HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa 3. restrictanonymous과 restrictanonymoussam의 값을 1로 변경 ￭ 로컬 보안 정책에서 변경 시작 → 프로그램 → 관리도구 → 로컬 보안 정책 → 보안 옵션에서 “네트워크 액세스: SAM 계정과 공유의 익명 열거 허용 안 함” 정책과 “네트워크 액세스: SAM 계정의 익명 열거 허용 안 함” 정책을 모두 “사용”으로 설정 [주요기반시설 가이드] 레지스트리 값 또는, 로컬 보안 정책 설정 [상세 조치 사례] l Windows NT Step 1) 시작 > 제어판 > 관리 도구 > 레지스트리 편집기 HKLM\SYSTEM\CurrentControlSet\Control\LSA Step 2) RestrictAnonymous 값을 “1”로 설정 l Windows 2000 Step 1) 시작 > 실행 > SECPOL.MSC > 로컬 정책 > 보안 옵션 Step 2) “익명의 연결에 추가적인 제한”에 “명백한 익명의 사용 권한이 없으면 액세스 제한” 선택 l Windows 2003, 2008, 2012, 2016, 2019, 2022 Step 1) 시작 > 제어판 > 관리 도구 > 로컬 보안 정책 > 로컬 정책 > 보안 옵션 Step 2) `"네트워크 액세스 : SAM 계정과 공유의 익명 열거 허용 안 함”과 “네트워크 액세스 : SAM 계정의 익명 열거 허용 안 함”에 “사용” 선택 [ 익명 열거 허용 안 함 사용 설정 ] 02. Windows 서버 253"

    try {
        $regResult = Get-ItemProperty -Path "Registry::HKLM\SYSTEM\CurrentControlSet\Control\LSA" -ErrorAction Stop 2>$null
        $curState = ($regResult | Format-List | Out-String).Trim()
        $detail = "레지스트리 값 확인됨. 수동 검증 필요."
        $status = "수동점검"
    } catch {
        $curState = "레지스트리 조회 실패: $_"
        $detail = "레지스트리 키 미존재 또는 접근 불가."
        $status = "수동점검"
    }

    Add-Result -Code "CSAP-Windows-29 / ISMS-W-51" -Category "보안 관리" -Title "SAM 계정과 공유의 익명 열거 허용 안함" `
        -Importance "상" -Status $status -Detail $detail `
        -Source "통합" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# CSAP-Windows-30 / ISMS-W-52: Autologon 기능 제어
function Check-CSAP_Windows_30 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "[클라우드 가이드] ￭ 레지스트리에서 변경 시작 → 실행 → regedit → HKEY_LOCAL_MACHINE\ Software\Microsoft\ Windows NT\CurrentVersion\Winlogon에서 AutoAdminLogon 값을 0 으로 설정 ※ AutoAdminLogon 값이 없을 경우 새로 만들기 → 다중 문자열 값 → AutoAdminLogon으로 이름 바꾸기 → 값 데이터 “0” 입력 [주요기반시설 가이드] 해당 레지스트리 값이 존재하는 경우 0으로 설정 [상세 조치 사례] l Windows NT, 2000, 2003, 2008, 2012, 2016, 2019, 2022 Step 1) 시작 > 제어판 > 관리 도구 > 레지스트리 편집기 HKLM\SOFTWARE\Microsoft\WindowsNT\CurrentVersion\Winlogon Step 2) “AutoAdminLogon” 값을 “0”으로 설정 Step 3) “Default Password” 존재 시 제거 [ AutoAdminLogon 값 확인 ] 254"

    try {
        $regResult = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Microsoft\WindowsNT\CurrentVersion\Winlogon" -ErrorAction Stop 2>$null
        $curState = ($regResult | Format-List | Out-String).Trim()
        $detail = "레지스트리 값 확인됨. 수동 검증 필요."
        $status = "수동점검"
    } catch {
        $curState = "레지스트리 조회 실패: $_"
        $detail = "레지스트리 키 미존재 또는 접근 불가."
        $status = "수동점검"
    }

    Add-Result -Code "CSAP-Windows-30 / ISMS-W-52" -Category "Windows 서버 > 5. 보안 관리" -Title "Autologon 기능 제어" `
        -Importance "상" -Status $status -Detail $detail `
        -Source "통합" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# CSAP-Windows-31 / ISMS-W-53: 이동식 미디어 포맷 및 꺼내기 허용
function Check-CSAP_Windows_31 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "[클라우드 가이드] ￭ 레지스트리에서 변경 시작 → 실행 → regedit → HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ Windows NT\CurrentVersion\Winlogon 에서 AllocateDASD 값을 `"0`" 으로 변경 ※ Windows Server 2022의 경우 default 설정이 allocatedasd 값이 없으므로 신규로 생성하여 데이터 값을 0으로 지정 ￭ 로컬 보안 정책에서 변경 시작 → 프로그램 → 관리도구 → 로컬 보안 정책 → 로컬 정책 → 보안 옵션 → `"장치 : 이동식 미디어 포맷 및 꺼내기 허용” 정책을 `"Administrators`" 으로 설정 [주요기반시설 가이드] “이동식 NTFS 미디어 꺼내기 허용” 정책을 “Administrators”로 설정 [상세 조치 사례] l Windows NT, 2000 Step 1) 시작 > 실행 > SECPOL.MSC > 로컬 정책 > 보안 옵션 Step 2) “이동식 NTFS 미디어 꺼내기 허용” 정책을 “Administrators”로 설정 l Windows 2003, 2008, 2012, 2016, 2019, 2022 Step 1) 시작 > 제어판 > 관리 도구 > 로컬 보안 정책 > 로컬 정책 > 보안 옵션 Step 2) “장치 : 이동식 미디어 포맷 및 꺼내기 허용” 정책을 “Administrators”로 설정 [ 이동식 미디어 포맷 및 꺼내기 허용 ] 02. Windows 서버 255"

    try {
        $curState = "레지스트리 경로 미지정"
        $detail = "수동 점검 필요. “이동식 미디어 포맷 및 꺼내기 허용” 정책이 “Administrators”로 되어있는 경우"
        $status = "수동점검"
    } catch {
        $curState = "레지스트리 조회 실패: $_"
        $detail = "레지스트리 키 미존재 또는 접근 불가."
        $status = "수동점검"
    }

    Add-Result -Code "CSAP-Windows-31 / ISMS-W-53" -Category "보안 관리" -Title "이동식 미디어 포맷 및 꺼내기 허용" `
        -Importance "상" -Status $status -Detail $detail `
        -Source "통합" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# CSAP-Windows-05: 패스워드 최대 사용 기간 설정
function Check-CSAP_Windows_05 {
    $status = "양호"
    $detail = ""
    $cmd = "secedit /export /cfg /c:\cfg.txt"
    $curState = ""
    $remediation = "[CLI] ￭ 명령 프롬프트에서 변경 시작 → 실행 → cmd → net accounts /MAXPWAGE:90 명령어 실행 ※ cmd를 관리자 권한으로 실행 [GUI] ￭ 로컬 보안 정책에서 변경 시작 → 프로그램 → 관리도구 → 로컬 보안 정책 → 계정 정책 → 암호 정책 → `"최대 암호 사용 기간`" 을 90일 이하로 설정"

    # Export security policy
    $tempFile = "$env:TEMP\secedit_export.cfg"
    secedit /export /cfg $tempFile 2>$null | Out-Null
    if (Test-Path $tempFile) {
        $content = Get-Content $tempFile | Select-String "MaximumPasswordAge"
        if ($content) {
            $curState = $content.ToString().Trim()
            $numericValue = Get-FirstNumber $curState
            if ($null -eq $numericValue) {
                $status = "수동점검"
                $detail = "최대 암호 사용 기간이 90일 이하일 경우"
            } elseif ($numericValue -le 90) {
                $status = "양호"
                $detail = "최대 암호 사용 기간이 90일 이하일 경우"
            } else {
                $status = "취약"
                $detail = "최대 암호 사용 기간이 90일 초과일 경우"
            }
        } else {
            $curState = "MaximumPasswordAge 설정 미발견"
            $detail = "보안정책 MaximumPasswordAge 미설정."
            $status = "취약"
        }
        Remove-Item $tempFile -Force 2>$null
    } else {
        $curState = "secedit 내보내기 실패"
        $detail = "보안정책 내보내기 실패."
        $status = "N/A"
    }

    Add-Result -Code "CSAP-Windows-05" -Category "계정 관리" -Title "패스워드 최대 사용 기간 설정" `
        -Importance "-" -Status $status -Detail $detail `
        -Source "클라우드" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# CSAP-Windows-06: 암호 사용 기간 제한없음 제거
function Check-CSAP_Windows_06 {
    $status = "양호"
    $detail = ""
    $cmd = "net user"
    $curState = ""
    $remediation = "[CLI] ￭ 명령 프롬프트에서 변경 시작 → 실행 → cmd → wmic useraccount where name=`"계정명`" set passwordexpires=true 명령어 입력 ※ cmd를 관리자 권한으로 실행 [GUI] ￭ 로컬 보안 정책에서 변경 시작 → 프로그램 → 관리도구 → 컴퓨터 관리 → 로컬 사용자 및 그룹 → 사용자 → 설정할 계정 선택 → 속성에서 `"암호 사용 기간 제한 없음`" 해제"

    try {
        $output = net user 2>$null
        $curState = ($output | Out-String).Trim()
        $detail = "사용자 계정 목록 확인됨. 수동 검증 필요."
        $status = "수동점검"
    } catch {
        $curState = "net user 실행 실패"
        $detail = "계정 조회 실패."
        $status = "N/A"
    }

    Add-Result -Code "CSAP-Windows-06" -Category "계정 관리" -Title "암호 사용 기간 제한없음 제거" `
        -Importance "-" -Status $status -Detail $detail `
        -Source "클라우드" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# CSAP-Windows-13: FTP 서비스 구동 점검
function Check-CSAP_Windows_13 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "[CLI] ￭ 명령 프롬프트에서 변경 1. 시작 → 실행 → cmd → net stop ftpsvc 명령어 실행 2. cmd → sc config ftpsvc start= disabled 명령어 실행 ※ cmd를 관리자 권한으로 실행 [GUI] ￭ 서비스에서 변경 시작 → 프로그램 → 관리도구 → ‘서비스’에서 ‘Microsoft FTP Service’를 중지하고, 시작유형을 `"사용 안 함`"으로 설정"

    $status = "수동점검"
    $detail = "서비스 상태 수동 확인 필요. FTP 서비스가 구동 중이지 않은 경우"
    $curState = "수동점검 필요"

    Add-Result -Code "CSAP-Windows-13" -Category "서비스 관리" -Title "FTP 서비스 구동 점검" `
        -Importance "-" -Status $status -Detail $detail `
        -Source "클라우드" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# CSAP-Windows-15: Anonymous FTP 금지
function Check-CSAP_Windows_15 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "￭ 인터넷 정보 서비스(IIS) 관리에서 변경 시작 → 프로그램 → 관리도구 → IIS(인터넷 정보 서비스) 관리자 → 사용중인 FTP 서비스 → FTP 인증 에서 `"익명 인증`" 을 `"사용 안 함`" 으로 설정"

    $status = "수동점검"
    $detail = "서비스 상태 수동 확인 필요. FTP를 사용하지 않거나 `"익명 연결 허용`" 이"
    $curState = "수동점검 필요"

    Add-Result -Code "CSAP-Windows-15" -Category "서비스 관리" -Title "Anonymous FTP 금지" `
        -Importance "-" -Status $status -Detail $detail `
        -Source "클라우드" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# CSAP-Windows-19: 최신 서비스팩 적용
function Check-CSAP_Windows_19 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "[Win2012] ￭ Microsoft 2012 보안 패치 사이트(Windows 2012 R2, 2020년 12월 기준) https://support.microsoft.com/ko-kr/help/4009470 ※ 일반 지원 종료일 : 2018년 10월 09일 연장 지원 종료일 : 2023년 10월 10일 참고) https://docs.microsoft.com/ko-kr/lifecycle/products/windows-server-2012-r2 [Win2016] ￭ Microsoft 2016 보안 패치 사이트(Windows 2016, 2020년 12월 현재) https://support.microsoft.com/ko-kr/help/4043454 ※ 일반 지원 종료일 : 2022년 01월 11일 연장 지원 종료일 : 2027년 01월 12일 참고) https://docs.microsoft.com/ko-kr/lifecycle/products/windows-server-2016 [Win2019] ￭ Microsoft 2019 보안 패치 사이트(Windows 2019, 2020년 12월 기준) https://support.microsoft.com/ko-kr/help/4581839 ※ 일반 지원 종료일 : 2024년 01월 09일 연장 지원 종료일 : 2029년 01월 09일 참고) https://support.microsoft.com/ko-kr/lifecycle/search/1163"

    $status = "수동점검"
    $detail = "서비스 상태 수동 확인 필요. 최신 보안패치가 적용된 서비스 팩이"
    $curState = "수동점검 필요"

    Add-Result -Code "CSAP-Windows-19" -Category "패치 및 로그 관리" -Title "최신 서비스팩 적용" `
        -Importance "-" -Status $status -Detail $detail `
        -Source "클라우드" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# CSAP-Windows-22: 로그의 정기적 검토 및 보고
function Check-CSAP_Windows_22 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "￭ 로그 기록에 대한 정기적 검토 및 분석 실시 (1) 시작 → 제어판 → 관리 도구 → 이벤트 뷰어 (2) 응용 프로그램 로그, 보안 로그, 시스템 로그 분석 (3) OS 구성에 따라 디렉터리 서비스 로그, 파일 복제 서비스 로그, DNS 서버 로그 등 분석 ※ 이벤트 로그를 확인하기 위해서 Windows 서버의 이벤트 뷰어를 사용하여 진행함 ￭ 로그 기록에 대한 정기적 검토 및 분석 실시 후 분석 결과에 대한 일일·월간 보고서 작성 및 보고"

    $status = "수동점검"
    $detail = "서비스 상태 수동 확인 필요. 로그 기록에 대해 정기적으로 검토, 분석, 리포트"
    $curState = "수동점검 필요"

    Add-Result -Code "CSAP-Windows-22" -Category "패치 및 로그 관리" -Title "로그의 정기적 검토 및 보고" `
        -Importance "-" -Status $status -Detail $detail `
        -Source "클라우드" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# ISMS-W-08: 계정 잠금 기간 설정
function Check-ISMS_W_08 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "“계정 잠금 기간” 및 “잠금 기간 원래대로 설정 기간” 60분 이상으로 설정 [상세 조치 사례] l Window NT Step 1) 시작 > 프로그램 > 관리 도구 > 도메인 사용자 관리자 > 정책 > 계정 정책 Step 2) “횟수 다시 설정”을 “60분”으로 설정, “잠금 유지 기간”의 “시간제한”을 “60분”으로 설정 l Windows 2000, 2003, 2008, 2012, 2016, 2019, 2022 Step 1) 시작 > 제어판 > 관리 도구 > 로컬 보안 정책 > 계정 정책 > 계정 잠금 정책 Step 2) “계정 잠금 기간”, “다음 시간 후 계정 잠금 수를 원래대로 설정”에 대해 각각 “60분” 설정 [ 계정 잠금 정책 설정 ] 02. Windows 서버 187"

    $status = "수동점검"
    $detail = "수동 점검 필요 항목입니다. “계정 잠금 기간” 및 “계정 잠금 기간 원래대로 설정 기간”이 60분 이상으로 설정된 경우"
    $curState = "수동점검 필요"

    Add-Result -Code "ISMS-W-08" -Category "Windows 서버 > 1. 계정 관리" -Title "계정 잠금 기간 설정" `
        -Importance "중" -Status $status -Detail $detail `
        -Source "주요기반시설" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# ISMS-W-09: 비밀번호 관리 정책 설정
function Check-ISMS_W_09 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "비밀번호 복잡성, 최소 비밀번호 길이, 최대/최소 사용 기간을 기준에 맞게 설정 [상세 조치 사례] l Windows NT Step 1) 시작 > 프로그램 > 관리 도구 > 도메인 사용자 관리자 > 정책 > 계정 Step 2) “최소 암호 길이”에 “최소”를 “8문자”로 설정 Step 3) “최대 암호 사용 기간”의 “사용 기간”을 “90일”로 설정 Step 4) “최소 암호 사용 기간”에서 “사용 기간”을 “1일”로 설정 Step 5) “암호 유일성”에서 “기억”을 “4개”로 설정 l Windows NT, 2000, 2003, 2008, 2012, 2016, 2019, 2022 Step 1) 시작 > 제어판 > 관리 도구 > 로컬 보안 정책 > 계정 정책 > 암호 정책 Step 2) “암호는 복잡성을 만족해야 함”을 “사용”으로 설정 Step 3) “최근 암호 기억”을 “4개 암호 기억됨”으로 설정 Step 4) “최대 암호 사용 기간”의 다음 이후 암호 만료 기간을 “90일”로 설정 Step 5) “최소 암호 길이”를 “8문자”로 설정 Step 6) “최소 암호 사용 기간”을 “1일”로 설정 [ 암호 정책 설정 ] ※ 해당 정책 설정은 비밀번호를 변경하거나 새로운 비밀번호 생성 시 아래와 같은 일련의 규정을 만족하는지 결정함. 영문, 숫자, 특수문자 중 2종류 이상을 조합하여 최소 10자리 이상 또는 3종류 이상을 조합하여 최소 8자리 이상의 길이로 구성 가. 영문 대문자(26개) 나. 영문 소문자(26개) 다. 숫자(10개) 라. 특수문자(32개) 02. Windows 서버 189"

    $status = "수동점검"
    $detail = "수동 점검 필요 항목입니다. 계정 비밀번호 관리 정책이 모두 적용된 경우"
    $curState = "수동점검 필요"

    Add-Result -Code "ISMS-W-09" -Category "Windows 서버 > 1. 계정 관리" -Title "비밀번호 관리 정책 설정" `
        -Importance "상" -Status $status -Detail $detail `
        -Source "주요기반시설" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# ISMS-W-10: 마지막 사용자 이름 표시 안 함
function Check-ISMS_W_10 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "※ Windows NT: 마지막으로 로그온한 사용자 이름 표시 안 함 설정 ※ Windows 2000: 로그온 스크린에 마지막 사용자 이름 표시 안 함 사용 설정 ※ Windows 2003, 2008, 2012, 2016, 2019, 2022: 대화형 로그온: 마지막 사용자 이름 표시 안 함 사용 설정 [상세 조치 사례] l Windows NT Step 1) 시작 > 프로그램 > 관리 도구 > 시스템 정책 편집기 > 파일 > 레지스트리 열기 > 로컬 컴퓨터 > 편집 > 등 록 정보 > Windows NT 시스템 > 로그온 > “마지막으로 로그온한 사용자 이름 표시 안 함”을 설정한 후 저장 l Windows 2000 Step 1) 시작 > 제어판 > 관리 도구 > 로컬 보안 정책 > 로컬 정책 > 보안 옵션 Step 2) “로그온 스크린에 마지막 사용자 이름 표시 안 함”을 “사용”으로 설정 l Windows 2003, 2008, 2012, 2016, 2019, 2022 Step 1) 시작 > 제어판 > 관리 도구 > 로컬 보안 정책 > 로컬 정책 > 보안 옵션 Step 2) “대화형 로그온: 마지막 사용자 이름 표시 안 함”을 “사용”으로 설정 [ 마지막 로그인 사용자 이름 표시 안 함 ] 02. Windows 서버 191"

    $status = "수동점검"
    $detail = "수동 점검 필요 항목입니다. “마지막 사용자 이름 표시 안 함”이 “사용”으로 설정된 경우"
    $curState = "수동점검 필요"

    Add-Result -Code "ISMS-W-10" -Category "Windows 서버 > 1. 계정 관리" -Title "마지막 사용자 이름 표시 안 함" `
        -Importance "중" -Status $status -Detail $detail `
        -Source "주요기반시설" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# ISMS-W-11: 로컬 로그온 허용
function Check-ISMS_W_11 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "Administrators, IUSR_ 외 다른 계정 및 그룹의 로컬 로그온 제한 [상세 조치 사례] l Windows NT, 2000, 2003, 2008, 2012, 2016, 2019, 2022 Step 1) 시작 > 제어판 > 관리 도구 > 로컬 보안 정책 > 로컬 정책 > 사용자 권한 할당 Step 2) “로컬 로그온 허용(또는, 로컬 로그온)” 정책에 “Adminstrators”, “IUSR_” 외 다른 계정 및 그룹 제거 [ 로컬 로그온 허용 정책 설정 ] 192"

    $status = "수동점검"
    $detail = "수동 점검 필요 항목입니다. 로컬 로그온 허용 정책에 Administrators, IUSR_ 만 존재하는 경우"
    $curState = "수동점검 필요"

    Add-Result -Code "ISMS-W-11" -Category "Windows 서버 > 1. 계정 관리" -Title "로컬 로그온 허용" `
        -Importance "중" -Status $status -Detail $detail `
        -Source "주요기반시설" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# ISMS-W-12: 익명 SID/이름 변환 허용 해제
function Check-ISMS_W_12 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "“네트워크 액세스: 익명 SID/이름 변환 허용” 정책 “사용 안 함” 설정 [상세 조치 사례] l Windows 2003, 2008, 2012, 2016, 2019, 2022 Step 1) 시작 > 제어판 > 관리 도구 > 로컬 보안 정책 > 로컬 정책 > 보안 옵션 Step 2) “네트워크 액세스: 익명 SID/이름 변환 허용” 정책이 “사용 안 함”으로 설정 [익명 SID/이름 변환 허용] ※ Windows Server 2000 이하 버전 해당 사항 없음 02. Windows 서버 193"

    $status = "수동점검"
    $detail = "수동 점검 필요 항목입니다. “익명 SID/이름 변환 허용” 정책이 “사용 안 함”으로 설정된 경우"
    $curState = "수동점검 필요"

    Add-Result -Code "ISMS-W-12" -Category "Windows 서버 > 1. 계정 관리" -Title "익명 SID/이름 변환 허용 해제" `
        -Importance "중" -Status $status -Detail $detail `
        -Source "주요기반시설" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# ISMS-W-13: 콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한
function Check-ISMS_W_13 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "“계정: 콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한” 정책을 “사용”으로 설정 [상세 조치 사례] l Windows 2003, 2008, 2012, 2016, 2019, 2022 Step 1) 시작 > 제어판 > 관리 도구 > 로컬 보안 정책 > 로컬 정책 > 보안 옵션 Step 2) “계정: 콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한” 정책을 “사용”으로 설정 [ 콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한 설정 ] 194"

    $status = "수동점검"
    $detail = "수동 점검 필요 항목입니다. “콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한” 정책이 “사용”인 경우"
    $curState = "수동점검 필요"

    Add-Result -Code "ISMS-W-13" -Category "Windows 서버 > 1. 계정 관리" -Title "콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한" `
        -Importance "중" -Status $status -Detail $detail `
        -Source "주요기반시설" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# ISMS-W-14: 원격터미널 접속 가능한 사용자 그룹 제한
function Check-ISMS_W_14 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "관리자 계정과 이외의 계정을 생성, 권한을 제한 사용 설정 [상세 조치 사례] l Windows 2003 Step 1) 제어판 > 사용자 계정 > 관리자 계정 이외의 계정 생성한 후 Step 2) 제어판 > 시스템 > [원격] 탭 > [원격] 탭 메뉴에서 “사용자가 이 컴퓨터에 원격으로 연결할 수 있음”에 체크 > “원격 사용자 선택”에서 원격 사용자 지정 후 확인 l Windows 2008 Step 1) 제어판 > 사용자 계정 > 관리자 계정 이외의 계정 생성한 후 Step 2) 제어판 > 시스템 > 원격 설정 > [원격] 탭 > [원격 데스크톱] 메뉴 > “모든 버전의 원격 데스크톱을 실행 중인 컴퓨터에서 연결 허용(보안 수준 낮음)” 또는 “네트워크 수준 인증을 사용하여 원격 데스크톱을 실 행하는 컴퓨터에서만 연결 허용(보안 수준 높음)” 중 하나에 체크 > “사용자 선택”에서 원격 사용자 지정 후 확인 02. Windows 서버 l Windows 2012, 2016, 2019, 2022 Step 1) 시작 > 제어판 > 사용자 계정 > 계정 관리 > 관리자 계정 이외의 계정 생성 Step 2) 시작 > 제어판 > 시스템 > 원격 설정 > [원격] 탭 > [원격 데스크톱] 메뉴 > “이 컴퓨터에 대한 원격 연결 허용” 에 체크 > “사용자 선택”에서 원격 사용자 지정 후 확인 [ 원격 데스크톱 사용자 지정 설정 ] 196"

    $status = "수동점검"
    $detail = "수동 점검 필요 항목입니다. (관리자 계정을 제외한) 원격 접속이 가능한 계정을 생성하여 타 사용자의 원격 접속을 제한하고,"
    $curState = "수동점검 필요"

    Add-Result -Code "ISMS-W-14" -Category "Windows 서버 > 1. 계정 관리" -Title "원격터미널 접속 가능한 사용자 그룹 제한" `
        -Importance "중" -Status $status -Detail $detail `
        -Source "주요기반시설" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# ISMS-W-15: 사용자 개인키 사용 시 암호 입력
function Check-ISMS_W_15 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "“시스템 암호화: 컴퓨터에 저장된 사용자 키에 대해 강력한 키 보호 사용” 정책을 “키를 사용할 때마다 암호를 매 번 입력해야 함”으로 적용 [상세 조치 사례] l Windows 2016, 2019, 2022 Step 1) 시작 > 제어판 > 관리 도구 > 로컬 보안 정책 > 로컬 정책 > 보안 옵션 Step 2) “시스템 암호화: 컴퓨터에 저장된 사용자 키에 대해 강력한 키 보호 사용” 정책을 “키를 사용할 때마다 암호를 매 번 입력해야 함”으로 적용 [ 컴퓨터에 저장된 사용자 키에 대해 강력한 키 보호 사용 설정 ] 02. Windows 서버 197"

    $status = "수동점검"
    $detail = "수동 점검 필요 항목입니다. 사용자 개인 키를 사용할 때마다 암호 입력을 받는 경우"
    $curState = "수동점검 필요"

    Add-Result -Code "ISMS-W-15" -Category "Windows 서버 > 2. 서비스 관리" -Title "사용자 개인키 사용 시 암호 입력" `
        -Importance "상" -Status $status -Detail $detail `
        -Source "주요기반시설" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# ISMS-W-19: 불필요한 IIS 서비스 구동 점검
function Check-ISMS_W_19 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "IIS 서비스가 불필요한 경우 IIS 서비스 중지 [상세 조치 사례] l Windows NT, 2000, 2003, 2008, 2012, 2016, 2019, 2022 Step 1) 시작 > 제어판 > 서비스 > World Wide Web Publishing 서비스(IISADMIN) > 속성 > `"시작 유형`"을 `"사 용 안 함`" 설정 후 중지 ※ IIS 미설치 시 SERVICES.MSC 에 출력되지 않음 [ IIS 서비스 사용 안 함 설정 ] 02. Windows 서버 205"

    $status = "수동점검"
    $detail = "서비스 상태 수동 확인 필요. IIS 서비스를 사용하지 않는 경우 또는 필요에 의해 IIS 서비스를 사용하는 경우"
    $curState = "수동점검 필요"

    Add-Result -Code "ISMS-W-19" -Category "Windows 서버 > 2. 서비스 관리" -Title "불필요한 IIS 서비스 구동 점검" `
        -Importance "상" -Status $status -Detail $detail `
        -Source "주요기반시설" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# ISMS-W-21: 암호화되지 않는 FTP 서비스 비활성화
function Check-ISMS_W_21 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "FTP 서비스가 필요하지 않다면 서비스 중지 또는 Secure FTP 응용 프로그램 사용 [상세 조치 사례] l Windows NT, 2000, 2003, 2008, 2012, 2016, 2019, 2022 Step 1) 시작 > 실행 > SERVICES.MSC > FTP Publishing Service(Windows 2012 이상 : Microsoft FTP Service) > 속성 > Step 2) 시작 유형을 “사용 안 함”으로 설정한 후, FTP 서비스 중지 [ FTP 서비스 사용 안 함 설정 ] 208"

    $status = "수동점검"
    $detail = "서비스 상태 수동 확인 필요. FTP 서비스를 사용하지 않는 경우 또는 Secure FTP 서비스를 사용하는 경우"
    $curState = "수동점검 필요"

    Add-Result -Code "ISMS-W-21" -Category "Windows 서버 > 2. 서비스 관리" -Title "암호화되지 않는 FTP 서비스 비활성화" `
        -Importance "상" -Status $status -Detail $detail `
        -Source "주요기반시설" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# ISMS-W-23: 공유 서비스에 대한 익명 접근 제한 설정
function Check-ISMS_W_23 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "공유 서비스를 사용하지 않는 경우 서비스 중지, 사용할 경우 익명 인증 사용 안 함 설정 적용 [상세 조치 사례] l Windows NT(IIS 4.0), 2000(IIS 5.0), 2003(IIS 6.0) Step 1) 인터넷 정보 서비스(IIS) 관리 > FTP 사이트 > 속성 > [보안 계정] 탭에서 “익명 연결 허용” 체크박스 해 제 (만약 개별 FTP 사이트에 적용할 경우 해당 사이트에만 설정이 적용되고, 기본 설정은 적용받지 않음) 02. Windows 서버 l Windows 2008(IIS 7.0), 2012(IIS 8.0), 2016, 2019, 2022(IIS 10.0) Step 1) 제어판 > 관리 도구 > 인터넷 정보 서비스(IIS) 관리 > 해당 FTP 사이트 > FTP 인증 선택 [ FTP 인증 설정 ] Step 2) FTP 인증 화면에서 익명 인증 사용 안 함 설정 [ 익명 인증 사용 안 함 설정 ] 212"

    $status = "수동점검"
    $detail = "서비스 상태 수동 확인 필요. 공유 서비스를 사용하지 않거나, 익명 인증 사용 안 함으로 설정된 경우"
    $curState = "수동점검 필요"

    Add-Result -Code "ISMS-W-23" -Category "Windows 서버 > 2. 서비스 관리" -Title "공유 서비스에 대한 익명 접근 제한 설정" `
        -Importance "상" -Status $status -Detail $detail `
        -Source "주요기반시설" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# ISMS-W-28: 터미널 서비스 암호화 수준 설정
function Check-ISMS_W_28 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "원격 데스크톱 서비스의 가동을 ‘중지’ 및 ‘사용 안 함’ 설정을 하거나, 부득이하게 사용할 경우 암호화 수준 설정 적용 [상세 조치 사례] l Windows NT Step 1) 시작 > 실행 > regedit Step 2) HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\ MinEncryptionLevel 값을 2(중간) 이상으로 설정 l Windows 2000 Step 1) 시작 > 실행 > TSCC.MSC > “해당 서비스” 선택 > 속성 Step 2) 암호화 수준 → 중간(Windows 2000) 이상으로 설정 02. Windows 서버 l Windows 2003 Step 1) Windows 2003: 시작 > 실행 > TSCC.MSC > “해당 서비스” 선택 > 속성 Step 2) [일반] 탭에서 암호화 수준 설정 → 클라이언트 호환 가능 l Windows 2008, 2012, 2016, 2019, 2022 Step 1) 시작 > 실행 > GPEDIT.MSC(로컬 그룹 정책 편집기) Step 2) 컴퓨터 구성 > 관리 템플릿 > 터미널 서비스 > 원격 데스크톱 세션 호스트 > 보안 Step 3) [클라이언트 연결 암호화 수준 설정] > [암호화 수준]을 클라이언트 호환 가능으로 설정 [ 암호화 수준 설정 ] ※ 원격 데스크톱 서비스가 필요한 경우 추가 보완 대책 1. 관리자 이외의 일반 사용자의 터미널 서비스 접속을 허용하지 않음 2. 방화벽에서 원격 데스크톱 서비스 포트의 사용을 관리자 컴퓨터의 IP로 제한 220"

    try {
        $regResult = Get-ItemProperty -Path "Registry::HKLM\SYSTEM\CurrentControlSet\Control\Terminal" -ErrorAction Stop 2>$null
        $curState = ($regResult | Format-List | Out-String).Trim()
        $detail = "레지스트리 값 확인됨. 수동 검증 필요."
        $status = "수동점검"
    } catch {
        $curState = "레지스트리 조회 실패: $_"
        $detail = "레지스트리 키 미존재 또는 접근 불가."
        $status = "수동점검"
    }

    Add-Result -Code "ISMS-W-28" -Category "Windows 서버 > 2. 서비스 관리" -Title "터미널 서비스 암호화 수준 설정" `
        -Importance "중" -Status $status -Detail $detail `
        -Source "주요기반시설" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# ISMS-W-29: 불필요한 SNMP 서비스 구동 점검
function Check-ISMS_W_29 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "불필요 시 서비스 중지/사용 안 함 [상세 조치 사례] l Windows 2000, 2003, 2008, 2012, 2016, 2019, 2022 Step 1) 불필요 시 해당 서비스 중지 시작 > 제어판 > 관리 도구 > 서비스 > SNMP Service(또는, SNMP 서비스) > 속성에서 “시작 유형”을 “사용 안 함”으로 설정한 후, SNMP 서비스 중지 [ SNMP 서비스 사용 안 함 설정 ] 02. Windows 서버 221"

    $status = "수동점검"
    $detail = "서비스 상태 수동 확인 필요. SNMP 서비스를 사용하지 않는 경우 또는 Community String을 설정하여 SNMP 서비스를"
    $curState = "수동점검 필요"

    Add-Result -Code "ISMS-W-29" -Category "Windows 서버 > 2. 서비스 관리" -Title "불필요한 SNMP 서비스 구동 점검" `
        -Importance "중" -Status $status -Detail $detail `
        -Source "주요기반시설" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# ISMS-W-31: SNMP Access Control 설정
function Check-ISMS_W_31 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "불필요 시 서비스 중지/사용 안 함, 사용 시 SNMP 패킷 수령 호스트 지정 [상세 조치 사례] l Windows 2000, 2003, 2008, 2012, 2016, 2019, 2022 Step 1) 시작 > 제어판 > 관리 도구 > 서비스 > SNMP Service(또는, SNMP 서비스) > 속성 > 보안 Step 2) “인증 트랩 보내기” 및 “다음 호스트로부터 SNMP 패킷 받아들이기” 선택 Step 3) SNMP 호스트 등록 [ SNMP 보안 설정 ] 02. Windows 서버 223"

    $status = "수동점검"
    $detail = "서비스 상태 수동 확인 필요. SNMP 서비스를 사용하지 않거나 특정 호스트로부터 SNMP 패킷 받아들이기가 설정된 경우"
    $curState = "수동점검 필요"

    Add-Result -Code "ISMS-W-31" -Category "Windows 서버 > 2. 서비스 관리" -Title "SNMP Access Control 설정" `
        -Importance "중" -Status $status -Detail $detail `
        -Source "주요기반시설" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# ISMS-W-32: DNS 서비스 구동 점검
function Check-ISMS_W_32 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "DNS 서비스의 동적 업데이트 비활성화 설정 [상세 조치 사례] l Windows 2000, 2003, 2008, 2012, 2016, 2019, 2022 Step 1) 시작 > 제어판 > 관리 도구 > DNS > 각 조회 영역 > 해당 영역 > 속성 > 일반 Step 2) 동적 업데이트 → 없음 (또는 아니오) 선택 [ 동적 업데이트 없음 설정 ] Step 3) 불필요 시 해당 서비스 중지 시작 > 제어판 > 관리 도구 > 서비스 > DNS Server > 속성 [일반] 탭에서 `"시작 유형`"을 `"사용 안 함`"으로 설정한 후, DNS Server 서비스 중지 [ DNS Server 사용 안 함 설정 ] 02. Windows 서버 225"

    $status = "수동점검"
    $detail = "서비스 상태 수동 확인 필요. DNS 서비스를 사용하지 않거나 동적 업데이트 “없음(아니오)”으로 설정된 경우"
    $curState = "수동점검 필요"

    Add-Result -Code "ISMS-W-32" -Category "Windows 서버 > 2. 서비스 관리" -Title "DNS 서비스 구동 점검" `
        -Importance "중" -Status $status -Detail $detail `
        -Source "주요기반시설" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# ISMS-W-33: HTTP/FTP/SMTP 배너 차단
function Check-ISMS_W_33 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "사용하지 않는 경우 IIS 서비스 중지/사용 안 함, 사용 시 속성값 수정 [상세 조치 사례] l HTTP [Server 헤더 제거] Step 1) Microsoft 다운로드 센터에서 URL Rewrite 다운로드 후 설치 https://www.iis.net/downloads/microsoft/url-rewrite Step 2) 제어판 > 관리 도구 > IIS(인터넷 정보 서비스) 관리자 > 해당 웹 사이트 > [URL 재작성] Step 3) 작업 탭 > [서버 값 관리 – 서버 변수 보기...] > 서버 변수 이름 추가 [ 서버 변수 추가 ] Step 4) [URL 재작성] > 작업 탭 > [규칙 추가...] > 아웃바운드 규칙 > 빈 규칙 > 다음 사항 적용 - 이름(N): Remove Server - 검색 범위: 서버 변수 - 서버 변수 이름: RESPONSE_SERVER - 패턴(T): .* [ 아웃바운드 규칙 추가 ] [X-Powered-By 헤더 제거] Step 1) 제어판 > 관리 도구 > IIS(인터넷 정보 서비스) 관리자 > 해당 웹 사이트 > [HTTP 응답 헤더] Step 2) [X-Powered-By] 설정 제거 [ X-Powered-By 헤더 제거 ] 02. Windows 서버 l FTP Step 1) IIS(인터넷 정보 서비스) 관리자 > FTP 메시지 > 기본 배너 숨기기 설정 [ FTP 기본 배너 숨기기 설정 ] l SMTP Step 1) 시작 > 실행 > cmd > adsutil.vbs 파일이 있는 디렉터리로 이동 - 명령어: cd C:\inetpub\AdminScripts - adsutil.vbs를 사용하기 위해 서버 관리자에서 역할 추가 필요 → ”웹 서버(IIS) > 관리 도구 > IIS 6 관리 호환성 > IIS 6 스크립팅 도구“ 설치 필요 Step 2) IIS에서 서비스 중인 SMTP 서비스 목록 확인 - 명령어: cscript adsutil.vbs enum /p smtpsvc Step 3) SMTP 서비스에 connectresponse 속성 값에서 배너 문구 수정 - 명령어: cscript adsutil.vbs set smtpsvc/1/connectresponse “Banner Text” Step 4) SMTP 서비스 재시작 - 명령어: net stop smtpsvc (중지) - 명령어: net start smtpsvc (시작) 228"

    $status = "수동점검"
    $detail = "서비스 상태 수동 확인 필요. HTTP, FTP, SMTP 접속 시 배너 정보가 보이지 않는 경우"
    $curState = "수동점검 필요"

    Add-Result -Code "ISMS-W-33" -Category "Windows 서버 > 2. 서비스 관리" -Title "HTTP/FTP/SMTP 배너 차단" `
        -Importance "하" -Status $status -Detail $detail `
        -Source "주요기반시설" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# ISMS-W-34: Telnet 서비스 비활성화
function Check-ISMS_W_34 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "불필요 시 서비스 중지/사용 안 함 설정, 사용 시 인증 방법으로 NTLM만 사용 [상세 조치 사례] l Windows NT, 2000 Step 1) 시작 > 설정 > 제어판 > 관리 도구 > 텔넷 서버 설정 Step 2) NTLM 인증 방식만 사용 l Windows 2003, 2008, 2012 Step 1) 시작 > 실행 > cmd > tlntadmn config Step 2) tlntadmn config sec = +NTLM -passwd (passwd 인증 방식을 제외하고 NTLM 방식만 사용) Step 3) 불필요 시 해당 서비스 중지 시작 > 실행 > SERVICES.MSC > Telnet > 속성 [일반] 탭에서 `"시작 유형`"을 `"사용 안 함`"으로 설정한 후 Telnet 서비스 중지 02. Windows 서버 229"

    $status = "수동점검"
    $detail = "서비스 상태 수동 확인 필요. Telnet 서비스가 구동되어 있지 않거나 인증 방법이 NTLM인 경우"
    $curState = "수동점검 필요"

    Add-Result -Code "ISMS-W-34" -Category "Windows 서버 > 2. 서비스 관리" -Title "Telnet 서비스 비활성화" `
        -Importance "중" -Status $status -Detail $detail `
        -Source "주요기반시설" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# ISMS-W-35: 불필요한 ODBC/OLE-DB 데이터 소스와 드라이브 제거
function Check-ISMS_W_35 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "사용하지 않는 불필요한 ODBC 데이터 소스 제거 [상세 조치 사례] l Windows NT Step 1) 시작 > 설정 > 제어판 > 데이터 원본(ODBC) > 시스템 DSN > 해당 드라이브 클릭 Step 2) 사용하지 않은 데이터 소스 제거 l Windows 2000, 2003, 2008, 2012, 2016, 2019, 2022 Step 1) 시작 > 제어판 > 관리 도구 > ODBC 데이터 원본 > 시스템 DSN > 해당 드라이브 클릭 Step 2) 사용하지 않는 데이터 소스 제거 [ 불필요 ODBC 데이터 소스 확인 및 제거 ] 230"

    $status = "수동점검"
    $detail = "수동 점검 필요 항목입니다. 시스템 DSN 부분의 데이터 소스를 현재 사용하고 있는 경우"
    $curState = "수동점검 필요"

    Add-Result -Code "ISMS-W-35" -Category "Windows 서버 > 2. 서비스 관리" -Title "불필요한 ODBC/OLE-DB 데이터 소스와 드라이브 제거" `
        -Importance "중" -Status $status -Detail $detail `
        -Source "주요기반시설" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# ISMS-W-36: 원격터미널 접속 타임아웃 설정
function Check-ISMS_W_36 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "Timeout 제어 설정 적용 [상세 조치 사례] l Windows 2000, 2003, 2008 Step 1) 시작 > 실행 > 열기 > TSCC.MSC 실행(Windows 2008은 TSCONFIG.MC) Step 2) RDP-Tcp connection에서 우클릭 > 속성 실행 Step 3) [세션] 탭에서 사용자 설정 무시(Override user settings)를 적용하고 유휴 시 세션이 끊어지도록 “유휴 세 션 제한 시간”을 “30분” 이하로 설정 02. Windows 서버 l Windows 2012, 2016, 2019, 2022 Step 1) 시작 > 실행 > GPEDIT.MSC(로컬 그룹 정책 편집기) Step 2) 컴퓨터 구성 > 관리 템플릿 > 터미널 서비스 > 원격 데스크톱 세션 호스트 > 세션 시간 제한 > Step 3) [활성 상태지만 유휴 터미널 서비스 세션에 시간 제한 설정] > [유휴 세션 제한]을 30분 이하로 설정 [ 유휴 세션 제한 설정 ] 232"

    $status = "수동점검"
    $detail = "서비스 상태 수동 확인 필요. 원격 제어 시 Timeout 제어 설정을 30분 이하로 설정한 경우"
    $curState = "수동점검 필요"

    Add-Result -Code "ISMS-W-36" -Category "Windows 서버 > 2. 서비스 관리" -Title "원격터미널 접속 타임아웃 설정" `
        -Importance "중" -Status $status -Detail $detail `
        -Source "주요기반시설" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# ISMS-W-37: 예약된 작업에 의심스러운 명령이 등록되어 있는지 점검
function Check-ISMS_W_37 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "예약 작업에 대한 주기적인 확인 [상세 조치 사례] l Windows 2000, 2003, 2008, 2012, 2016, 2019, 2022 Step 1) 시작 > 설정 > 제어판 > 예약된 작업 확인 Step 2) 등록된 예약 작업을 선택하여 상세 내역 확인 Step 3) 불필요한 작업 존재 시 삭제 [ 불필요한 작업 제거 ] ※ 2008, 2012, 2016, 2019 는 제어판 > 관리 도구 > 작업 스케줄러에서 확인 02. Windows 서버 233"

    $status = "수동점검"
    $detail = "수동 점검 필요 항목입니다. 불필요한 명령어나 파일 등 주기적인 예약 작업의 존재 여부를 주기적으로 점검하고 제거한 경우"
    $curState = "수동점검 필요"

    Add-Result -Code "ISMS-W-37" -Category "Windows 서버 > 2. 서비스 관리" -Title "예약된 작업에 의심스러운 명령이 등록되어 있는지 점검" `
        -Importance "중" -Status $status -Detail $detail `
        -Source "주요기반시설" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# ISMS-W-38: 주기적 보안 패치 및 벤더 권고사항 적용
function Check-ISMS_W_38 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "주기적인 보안 패치 확인 및 설치 적용 [상세 조치 사례] l Windows NT, 2000, 2003, 2008, 2012, 2016, 2019, 2022 [수동 HOT FIX 적용] Step 1) 패치 리스트를 조회하여, 서버에 필요한 패치를 선별하여 수동으로 설치함. https://technet.microsoft.com/ko-kr/security/ https://msrc.microsoft.com/update-guide [자동 HOT FIX 적용] Step 1) Windows 자동업데이트 기능을 이용한 설치 제어판 > windows update 234"

    $status = "수동점검"
    $detail = "수동 점검 필요 항목입니다. 패치 절차를 수립하여 주기적으로 패치를 확인 및 설치하는 경우"
    $curState = "수동점검 필요"

    Add-Result -Code "ISMS-W-38" -Category "Windows 서버 > 3. 패치 관리" -Title "주기적 보안 패치 및 벤더 권고사항 적용" `
        -Importance "상" -Status $status -Detail $detail `
        -Source "주요기반시설" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# ISMS-W-40: 정책에 따른 시스템 로깅 설정
function Check-ISMS_W_40 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "이벤트에 대한 감사 설정 [상세 조치 사례] l Windows NT Step 1) 시작 > 프로그램 > 관리 도구 > 도메인 사용자 관리자 > 정책 > 감사 § 로그온 및 로그오프, 보안 정책 바꾸기: 성공/실패 감사 § 사용자 권한 사용, 사용자 및 그룹 관리: 실패 감사 l Windows 2000, 2003, 2008, 2012, 2016, 2019, 2022 Step 1) 시작 > 제어판 > 관리 도구 > 로컬 보안 정책 > 로컬 정책 > 감사 정책 <감사 정책 권고 기준> § 계정 관리: 실패 감사 § 계정 로그온 이벤트 : 성공/실패 감사 § 권한 사용 : 성공/실패 감사 § 디렉터리 서비스 액세스 : 실패 감사 § 로그온 이벤트 : 성공/실패 감사 § 정책 변경 : 성공/실패 감사 [ 감사 정책 설정 ] 02. Windows 서버 237"

    $status = "수동점검"
    $detail = "서비스 상태 수동 확인 필요. 감사 정책 권고 기준에 따라 감사 설정이 되어 있는 경우"
    $curState = "수동점검 필요"

    Add-Result -Code "ISMS-W-40" -Category "Windows 서버 > 4. 로그 관리" -Title "정책에 따른 시스템 로깅 설정" `
        -Importance "중" -Status $status -Detail $detail `
        -Source "주요기반시설" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# ISMS-W-41: NTP 및 시각 동기화 설정
function Check-ISMS_W_41 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "NTP 및 시각 동기화 설정 [상세 조치 사례] l Windows 2000, 2003, 2008, 2012, 2016, 2019, 2022 [인터넷 동기화 설정 시] Step 1) 제어판 > 시계 및 국가 > 날짜 및 시간 > 인터넷 시간 > 설정 변경 > 인터넷 시간 서버와 동기화 Step 2) 신뢰할 수 있는 NTP 서버 입력 후 적용 [ NTP 설정 및 동기화 ] [내부 NTP 서버 사용 시] Step 1) 시간 동기화 정보 확인 (Client) CMD > w32tm /dumpreg /subkey:parameters Step 2) 내부 NTP서버로 시간동기화 설정 (Client) (설정) CMD > w32tm /config /syncfromflags:manual /manualpeerlist:{NTP서버 IP or 도메인} /update (적용 확인) CMD > w32tm /dumpreg /subkey:parameters ※ Client에서 동기화 설정 후 ‘SpecialPollInterval’ ‘MaxPosPhaseCorrection’ 설정에 따라 주기적으로 자동으로 동기화가 적용되지만 NTP Server에서 다음 명령어로 즉시 적용 가능함. CMD > w32tm /resync Step 1) 동기화 시간차 확인 CMD > w32tm /stripchart /dataonly /computer:{NTP서버 IP or 도메인} 02. Windows 서버 239"

    $status = "수동점검"
    $detail = "수동 점검 필요 항목입니다. NTP 및 시각 동기화를 설정한 경우"
    $curState = "수동점검 필요"

    Add-Result -Code "ISMS-W-41" -Category "Windows 서버 > 4. 로그 관리" -Title "NTP 및 시각 동기화 설정" `
        -Importance "중" -Status $status -Detail $detail `
        -Source "주요기반시설" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# ISMS-W-42: 이벤트 로그 관리 설정
function Check-ISMS_W_42 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "최대 로그 크기 “10,204KB”, “90일 이후 이벤트 덮어씀” 설정 [상세 조치 사례] l Windows NT, 2000, 2003, 2008, 2012, 2016, 2019, 2022 Step 1) 시작 > 제어판 > 관리 도구 > 이벤트 뷰어 > 해당 로그 > 속성 > 일반 Step 2) 최대 로그 크기 → 10240KB 최대 로그 크기에 도달할 때: 다음보다 오래된 이벤트 덮어쓰기 → 90일 [ 이벤트 로그 덮어쓰기 설정 ] ※ Windows 2008, 2012, 2016, 2019 서버의 경우 덮어쓰기 날짜 지정 불가능 240"

    $status = "수동점검"
    $detail = "수동 점검 필요 항목입니다. 최대 로그 크기 “10,240KB 이상”으로 설정, “90일 이후 이벤트 덮어씀”을 설정한 경우"
    $curState = "수동점검 필요"

    Add-Result -Code "ISMS-W-42" -Category "Windows 서버 > 4. 로그 관리" -Title "이벤트 로그 관리 설정" `
        -Importance "하" -Status $status -Detail $detail `
        -Source "주요기반시설" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# ISMS-W-43: 이벤트 로그 파일 접근 통제 설정
function Check-ISMS_W_43 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "로그 디렉터리의 접근 권한에 Everyone 제거 [상세 조치 사례] l Windows NT, 2000, 2003, 2008, 2012 Step 1) 탐색기 > 로그 디렉터리 > 속성 > 보안 Step 2) Everyone 권한 제거 l Windows 2016, 2019, 2022 Step 1) 탐색기 > 로그 디렉터리 > 속성 > 보안 > 고급 Step 2) Everyone 권한 제거 [ 로그 디렉터리 권한 확인 ] 02. Windows 서버 241"

    $status = "수동점검"
    $detail = "수동 점검 필요 항목입니다. 로그 디렉터리의 접근 권한에 Everyone 권한이 없는 경우"
    $curState = "수동점검 필요"

    Add-Result -Code "ISMS-W-43" -Category "Windows 서버 > 4. 로그 관리" -Title "이벤트 로그 파일 접근 통제 설정" `
        -Importance "중" -Status $status -Detail $detail `
        -Source "주요기반시설" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# ISMS-W-47: 화면 보호기 설정
function Check-ISMS_W_47 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "화면 보호기 사용, 대기 시간 10분 이하, 해제를 위한 암호 사용 [상세 조치 사례] l Windows NT, 2000 Step 1) 바탕화면 > 등록 정보 > 화면 보호기 Step 2) “암호 사용” 설정 및 대기 시간 “10분” 이하로 설정 l Windows 2003 Step 1) 바탕화면 > 마우스 우클릭 > 속성 > 디스플레이 등록 정보 > [화면 보호기] Step 2) `"다시 시작할 때 암호로 보호`" 설정 및 대기 시간 “10분” 이하로 설정 02. Windows 서버 l Windows 2008, 2012 Step 1) 제어판 > 디스플레이 > 화면 보호기 변경 Step 2) `"다시 시작할 때 로그온 화면 표시`" 설정 및 대기 시간 “10분” 이하로 설정 l Windows 2016, 2019, 2022 Step 1) 설정 > 개인 설정 > 잠금 화면 > 화면 보호기 설정 Step 2) `"다시 시작할 때 로그온 화면 표시`" 설정 및 대기 시간 “10분” 이하로 설정 [ 화면 보호기 설정 ] 246"

    $status = "수동점검"
    $detail = "수동 점검 필요 항목입니다. 화면 보호기를 설정하고 대기 시간이 10분 이하의 값으로 설정되어 있으며, 화면 보호기 해제를"
    $curState = "수동점검 필요"

    Add-Result -Code "ISMS-W-47" -Category "Windows 서버 > 5. 보안 관리" -Title "화면 보호기 설정" `
        -Importance "하" -Status $status -Detail $detail `
        -Source "주요기반시설" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# ISMS-W-54: Dos 공격 방어 레지스트리 설정
function Check-ISMS_W_54 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "레지스트리 값을 추가 또는 수정 [상세 조치 사례] l Windows NT, 2000, 2003, 2008, 2012, 2016, 2019, 2022 Step 1) 시작 > 제어판 > 관리 도구 > 레지스트리 편집기 HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\ 폴더 Step 2) 다음의 DoS 방어 레지스트리 값 추가 또는 변경 § SynAttackProtect = REG_DWORD 0(False) - > 1 이상 § EnableDeadGWDetect = REG_DWORD 1(True) - > 0 § KeepAliveTime = REG_DWORD 7,200,000(2시간) - > 300,000(5분) § NoNameReleaseOnDemand = REG_DWORD 0(False) - > 1 256"

    try {
        $regResult = Get-ItemProperty -Path "Registry::HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\" -ErrorAction Stop 2>$null
        $curState = ($regResult | Format-List | Out-String).Trim()
        $detail = "레지스트리 값 확인됨. 수동 검증 필요."
        $status = "수동점검"
    } catch {
        $curState = "레지스트리 조회 실패: $_"
        $detail = "레지스트리 키 미존재 또는 접근 불가."
        $status = "수동점검"
    }

    Add-Result -Code "ISMS-W-54" -Category "Windows 서버 > 5. 보안 관리" -Title "Dos 공격 방어 레지스트리 설정" `
        -Importance "중" -Status $status -Detail $detail `
        -Source "주요기반시설" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# ISMS-W-55: 사용자가 프린터 드라이버를 설치할 수 없게 함
function Check-ISMS_W_55 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "“사용자가 프린터 드라이버를 설치할 수 없게 함” 정책을 “사용”으로 설정 [상세 조치 사례] l Windows NT, 2000 Step 1) 시작 > 실행 > SECPOL.MSC > 로컬 정책 > 보안 옵션 Step 2) “사용자가 프린터 드라이버를 설치할 수 없게 함” 정책을 “사용”으로 설정 l Windows 2003, 2008, 2012, 2016, 2019, 2022 Step 1) 시작 > 제어판 > 관리 도구 > 로컬 보안 정책 > 로컬 정책 > 보안 옵션 Step 2) “장치: 사용자가 프린터 드라이버를 설치할 수 없게 함” 정책을 “사용”으로 설정 [ 장치: 사용자가 프린터 드라이버를 설치할 수 없게 함 적용 ] 02. Windows 서버 257"

    $status = "수동점검"
    $detail = "수동 점검 필요 항목입니다. “사용자가 프린터 드라이버를 설치할 수 없게 함” 정책이 “사용”인 경우"
    $curState = "수동점검 필요"

    Add-Result -Code "ISMS-W-55" -Category "Windows 서버 > 5. 보안 관리" -Title "사용자가 프린터 드라이버를 설치할 수 없게 함" `
        -Importance "중" -Status $status -Detail $detail `
        -Source "주요기반시설" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# ISMS-W-56: SMB 세션 중단 관리 설정
function Check-ISMS_W_56 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "Ÿ “로그인 시간이 만료되면 클라이언트 연결 끊기” 정책 “사용” 설정 Ÿ “세션 연결을 중단하기 전에 필요한 유휴 시간” 정책 “15분” 이하로 설정 [상세 조치 사례] l Windows NT, 2000 Step 1) 시작 > 실행 > SECPOL.MSC > 로컬 정책 > 보안 옵션 Step 2) “로그인 시간이 만료되면 클라이언트 연결 끊기” 정책 “사용” 설정 “세션 연결을 중단하기 전에 필요한 유휴 시간” 정책 “15분” 이하로 설정 l Windows 2003, 2008, 2012, 2016, 2019, 2022 Step 1) 시작 > 제어판 > 관리 도구 > 로컬 보안 정책 > 로컬 정책 > 보안 옵션 Step 2) “Microsoft 네트워크 서버: 로그온 시간이 만료되면 클라이언트 연결 끊기” 정책 “사용” 설정 “Microsoft 네트워크 서버: 세션 연결을 중단하기 전에 필요한 유휴 시간” 정책 “15분” 이하로 설정 [ 로그온 시간이 만료되면 클라이언트 연결 끊기 “사용” 설정 ] [ 세션을 중단하기 전에 필요한 유휴 시간 “15분” 설정 ] 02. Windows 서버 259"

    $status = "수동점검"
    $detail = "수동 점검 필요 항목입니다. “로그온 시간이 만료되면 클라이언트 연결 끊기” 정책을 “사용”으로, “세션 연결을 중단하기 전에"
    $curState = "수동점검 필요"

    Add-Result -Code "ISMS-W-56" -Category "Windows 서버 > 5. 보안 관리" -Title "SMB 세션 중단 관리 설정" `
        -Importance "중" -Status $status -Detail $detail `
        -Source "주요기반시설" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# ISMS-W-57: 로그온 시 경고 메시지 설정
function Check-ISMS_W_57 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "로그인 메시지 제목 및 메시지 내용에 경고 문구 삽입 [상세 조치 사례] l Windows NT Step 1) 시작 > 제어판 > 관리 도구 > 레지스트리 편집기 HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsNT\CurrentVersion\Winlogon Step 2) LegalNoticeCaption: 제목 Step 3) LegalNoticeText: 메시지 내용 ※ 변경된 레지스트리 키의 내용은 시스템을 로그오프 한 후 반영됨 l Windows 2000 Step 1) 시작 > 실행 > SECPOL.MSC > 로컬 정책 > 보안 옵션 Step 2) 로그온 시도하는 사용자에 대한 메시지 제목: 배너 제목 입력 Step 3) 로그온 시도하는 사용자에 대한 메시지 텍스트: 배너 내용 입력 l Windows 2003, 2008, 2012, 2016, 2019, 2022 Step 1) 시작 > 제어판 > 관리 도구 > 로컬 보안 정책 > 로컬 정책 > 보안 옵션 Step 2) 대화형 로그온: 로그온 시도하는 사용자에 대한 메시지 제목: 배너 제목 입력 Step 3) 대화형 로그온: 로그온 시도하는 사용자에 대한 메시지 텍스트: 배너 내용 입력 [ 로그온 시도 경고 메시지 설정 ] 02. Windows 서버 261"

    try {
        $curState = "레지스트리 경로 미지정"
        $detail = "수동 점검 필요. 로그인 경고 메시지 제목 및 내용이 설정된 경우"
        $status = "수동점검"
    } catch {
        $curState = "레지스트리 조회 실패: $_"
        $detail = "레지스트리 키 미존재 또는 접근 불가."
        $status = "수동점검"
    }

    Add-Result -Code "ISMS-W-57" -Category "Windows 서버 > 5. 보안 관리" -Title "로그온 시 경고 메시지 설정" `
        -Importance "하" -Status $status -Detail $detail `
        -Source "주요기반시설" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# ISMS-W-58: 사용자별 홈 디렉터리 권한 설정
function Check-ISMS_W_58 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "Everyone 권한 제거 [상세 조치 사례] l Windows NT Step 1) Windows NT: C:\WinNT\Profiles\사용자 홈 디렉터리 > 등록 정보 > 보안 Step 2) Everyone 권한 제거(All Users, Default User 디렉터리는 제외) l Windows 2000, 2003 Step 1) C:\Documents and Settings\사용자 홈 디렉터리 > 속성 > 보안 Step 2) Everyone 권한 제거(All Users, Default User 디렉터리는 제외) l Windows 2008 Step 1) C:\사용자\<사용자 계정> Step 2) 해당 사용자에 대한 권한 외 일반 계정 삭제 l Windows 2012, 2016, 2019, 2022 Step 1) C:\사용자\<사용자 계정> Step 2) 해당 사용자에 대한 권한 외 일반 계정 삭제 [ 사용자 권한 설정 확인 ] 02. Windows 서버 263"

    $status = "수동점검"
    $detail = "수동 점검 필요 항목입니다. 홈 디렉터리에 Everyone 권한이 없는 경우 (All Users, Default User 디렉터리 제외)"
    $curState = "수동점검 필요"

    Add-Result -Code "ISMS-W-58" -Category "Windows 서버 > 5. 보안 관리" -Title "사용자별 홈 디렉터리 권한 설정" `
        -Importance "중" -Status $status -Detail $detail `
        -Source "주요기반시설" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# ISMS-W-59: LAN Manager 인증 수준
function Check-ISMS_W_59 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "- Windows 2000 : LAN Manager 인증 7수준 - > NTLMv2 응답만 보내기 - Windows 2003, 2008, 2012, 2016, 2019 : 네트워크 보안: LAN Manager 인증 수준 - > NTMLv2 응답만 보내기 [상세 조치 사례] l Windows NT, 2000 Step 1) 시작 > 실행 > SECPOL.MSC > 로컬 정책 > 보안 옵션 Step 2) “LAN Manager 인증 수준” 정책에 “NTLMv2 응답만 보내기” 설정 l Windows 2003, 2008, 2012, 2016, 2019, 2022 Step 1) 시작 > 제어판 > 관리 도구 > 로컬 보안 정책 > 로컬 정책 > 보안 옵션 Step 2) “네트워크 보안: LAN Manager 인증 수준” 정책에 NTLMv2 응답만 보내기” 설정 [ LAN Manager 인증 수준 설정 ] 02. Windows 서버 265"

    $status = "수동점검"
    $detail = "수동 점검 필요 항목입니다. `"LAN Manager 인증 수준`" 정책에 `"NTLMv2 응답만 보냄`"이 설정되어 있는 경우"
    $curState = "수동점검 필요"

    Add-Result -Code "ISMS-W-59" -Category "Windows 서버 > 5. 보안 관리" -Title "LAN Manager 인증 수준" `
        -Importance "중" -Status $status -Detail $detail `
        -Source "주요기반시설" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# ISMS-W-60: 보안 채널 데이터 디지털 암호화 또는 서명
function Check-ISMS_W_60 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "보안 채널 데이터를 디지털 암호화·서명 관련 3개 정책 → 사용 [상세 조치 사례] l Windows NT, 2000 Step 1) 시작 > 실행 > SECPOL.MSC > 로컬 정책 > 보안 옵션 Step 2) 아래 3가지 정책을 모두 `"사용`"으로 설정 • 도메인 구성원: 보안 채널 데이터를 디지털 암호화 또는 서명 (항상) • 도메인 구성원: 보안 채널 데이터 디지털 서명 (가능한 경우) • 도메인 구성원: 보안 채널 데이터를 디지털 암호화 (가능한 경우) l Windows 2003, 2008, 2012, 2016, 2019, 2022 Step 1) 시작 > 제어판 > 관리 도구 > 로컬 보안 정책 > 로컬 정책 > 보안 옵션 Step 2) 아래 3가지 정책을 모두 `"사용`"으로 설정 • 도메인 구성원: 보안 채널 데이터를 디지털 암호화 또는 서명 (항상) • 도메인 구성원: 보안 채널 데이터 디지털 서명 (가능한 경우) • 도메인 구성원: 보안 채널 데이터를 디지털 암호화 (가능한 경우) [ 보안 채널 데이터 설정 적용 ] 02. Windows 서버 267"

    $status = "수동점검"
    $detail = "수동 점검 필요 항목입니다. 아래 3가지 정책 모두 “사용`"으로 되어있는 경우"
    $curState = "수동점검 필요"

    Add-Result -Code "ISMS-W-60" -Category "Windows 서버 > 5. 보안 관리" -Title "보안 채널 데이터 디지털 암호화 또는 서명" `
        -Importance "중" -Status $status -Detail $detail `
        -Source "주요기반시설" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# ISMS-W-61: 파일 및 디렉토리 보호
function Check-ISMS_W_61 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "FAT 파일 시스템을 사용 시 가능한 NTFS 파일 시스템 변환 설정 [상세 조치 사례] l Windows NTM, 2000, 2003, 2008, 2012, 2016, 2019, 2022 Step 1) 시작 > 실행 > CMD > fsutil fsinfo volumeinfo (해당 드라이브) Step 2) FAT 파일 시스템 사용 시 아래 명령으로 NTFS 변환 시작 > 실행 > CMD > convert 드라이브명: /fs:ntfs (예) convert F: /fs/ntfs라고 입력 시 F 드라이브는 NTFS 형식으로 변환됨 268"

    $status = "수동점검"
    $detail = "수동 점검 필요 항목입니다. NTFS 파일 시스템을 사용하는 경우"
    $curState = "수동점검 필요"

    Add-Result -Code "ISMS-W-61" -Category "Windows 서버 > 5. 보안 관리" -Title "파일 및 디렉토리 보호" `
        -Importance "중" -Status $status -Detail $detail `
        -Source "주요기반시설" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# ISMS-W-62: 시작 프로그램 목록 분석
function Check-ISMS_W_62 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "시작 프로그램 목록의 정기적인 검사 실시 및 불필요한 서비스 비활성화 설정 [상세 조치 사례] l Windows 2000, 2003, 2008 Step 1) 시작 > 검색 > msconfig Step 2) 시작 프로그램 탭 클릭 > 시작 프로그램 목록 중 불필요하거나 의심스러운 항목 체크 표시 해제 l Windows 2012, 2016, 2019, 2022 Step 1) Windows 2012 서버 이후 버전의 경우 시작 프로그램 목록 편집이 불가능하며 별도의 편집이나 등록을 위해서는 배치파일이나 레지스트리 값 추가를 이용해서 개인화를 통해 사용할 수 있으나 보안상 권장하 지 않음 02. Windows 서버 269"

    $status = "수동점검"
    $detail = "서비스 상태 수동 확인 필요. 시작 프로그램 목록을 정기적으로 검사하고 불필요한 서비스를 비활성화한 경우"
    $curState = "수동점검 필요"

    Add-Result -Code "ISMS-W-62" -Category "Windows 서버 > 5. 보안 관리" -Title "시작 프로그램 목록 분석" `
        -Importance "중" -Status $status -Detail $detail `
        -Source "주요기반시설" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# ISMS-W-63: 도메인 컨트롤러-사용자의 시간 동기화
function Check-ISMS_W_63 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "Kerberos 사용 시 컴퓨터 시계 동기화 최대 허용 오차값 5분 이하로 설정 [상세 조치 사례] l Windows 2012, 2016, 2019, 2022 Step 1) 시작 > 제어판 > 관리 도구 > 로컬 보안 정책 > 계정 정책 > Kerberos 정책 컴퓨터 시계 동기화 최대 허용 오차 5분으로 설정 [ 컴퓨터 시계 동기화 최대 허용 오차 ] 270"

    $status = "수동점검"
    $detail = "수동 점검 필요 항목입니다. 컴퓨터 시계 동기화 최대 허용 오차값이 5분 이하인 경우"
    $curState = "수동점검 필요"

    Add-Result -Code "ISMS-W-63" -Category "Windows 서버 > 5. 보안 관리" -Title "도메인 컨트롤러-사용자의 시간 동기화" `
        -Importance "중" -Status $status -Detail $detail `
        -Source "주요기반시설" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}

# ISMS-W-64: 윈도우 방화벽 설정
function Check-ISMS_W_64 {
    $status = "양호"
    $detail = ""
    $cmd = "수동점검 필요"
    $curState = ""
    $remediation = "Windows 방화벽 “사용”으로 설정 [상세 조치 사례] l Windows 2000, 2003, 2008, 2012, 2016, 2019, 2022 Step 1) 시작 > 제어판 > Windows Defender 방화벽 > Windows 방화벽 설정 또는 해제 (또는 시작 > 실행 > “firewall.cpl” 입력) Step 2) Windows Defender 방화벽 “사용” 설정 [ 방화벽 “사용” 설정 ]"

    $status = "수동점검"
    $detail = "수동 점검 필요 항목입니다. Windows 방화벽 “사용”으로 설정된 경우"
    $curState = "수동점검 필요"

    Add-Result -Code "ISMS-W-64" -Category "Windows 서버 > 5. 보안 관리" -Title "윈도우 방화벽 설정" `
        -Importance "중" -Status $status -Detail $detail `
        -Source "주요기반시설" -Command $cmd -CurrentState $curState `
        -Remediation $remediation
}


###############################################################################
# Execute all checks
###############################################################################

Write-Host "===== Windows CCE 취약점 진단 시작 =====" -ForegroundColor Cyan
Write-Host "호스트: $env:COMPUTERNAME"
Write-Host "날짜: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host ""

$totalChecks = 68
$currentCheck = 0

function Show-Progress {
    param([string]$CheckName)
    $script:currentCheck++
    Write-Progress -Activity "CCE 취약점 진단" -Status "$currentCheck/$totalChecks - $CheckName 점검 중..." -PercentComplete (($script:currentCheck / $totalChecks) * 100)
}


Show-Progress "CSAP-Windows-01"; Check-CSAP_Windows_01
Show-Progress "CSAP-Windows-02"; Check-CSAP_Windows_02
Show-Progress "CSAP-Windows-03"; Check-CSAP_Windows_03
Show-Progress "CSAP-Windows-04"; Check-CSAP_Windows_04
Show-Progress "CSAP-Windows-07"; Check-CSAP_Windows_07
Show-Progress "CSAP-Windows-08"; Check-CSAP_Windows_08
Show-Progress "CSAP-Windows-09"; Check-CSAP_Windows_09
Show-Progress "CSAP-Windows-10"; Check-CSAP_Windows_10
Show-Progress "CSAP-Windows-11"; Check-CSAP_Windows_11
Show-Progress "CSAP-Windows-12"; Check-CSAP_Windows_12
Show-Progress "CSAP-Windows-14"; Check-CSAP_Windows_14
Show-Progress "CSAP-Windows-16"; Check-CSAP_Windows_16
Show-Progress "CSAP-Windows-17"; Check-CSAP_Windows_17
Show-Progress "CSAP-Windows-18"; Check-CSAP_Windows_18
Show-Progress "CSAP-Windows-20"; Check-CSAP_Windows_20
Show-Progress "CSAP-Windows-21"; Check-CSAP_Windows_21
Show-Progress "CSAP-Windows-23"; Check-CSAP_Windows_23
Show-Progress "CSAP-Windows-24"; Check-CSAP_Windows_24
Show-Progress "CSAP-Windows-25"; Check-CSAP_Windows_25
Show-Progress "CSAP-Windows-26"; Check-CSAP_Windows_26
Show-Progress "CSAP-Windows-27"; Check-CSAP_Windows_27
Show-Progress "CSAP-Windows-28"; Check-CSAP_Windows_28
Show-Progress "CSAP-Windows-29"; Check-CSAP_Windows_29
Show-Progress "CSAP-Windows-30"; Check-CSAP_Windows_30
Show-Progress "CSAP-Windows-31"; Check-CSAP_Windows_31
Show-Progress "CSAP-Windows-05"; Check-CSAP_Windows_05
Show-Progress "CSAP-Windows-06"; Check-CSAP_Windows_06
Show-Progress "CSAP-Windows-13"; Check-CSAP_Windows_13
Show-Progress "CSAP-Windows-15"; Check-CSAP_Windows_15
Show-Progress "CSAP-Windows-19"; Check-CSAP_Windows_19
Show-Progress "CSAP-Windows-22"; Check-CSAP_Windows_22
Show-Progress "ISMS-W-08"; Check-ISMS_W_08
Show-Progress "ISMS-W-09"; Check-ISMS_W_09
Show-Progress "ISMS-W-10"; Check-ISMS_W_10
Show-Progress "ISMS-W-11"; Check-ISMS_W_11
Show-Progress "ISMS-W-12"; Check-ISMS_W_12
Show-Progress "ISMS-W-13"; Check-ISMS_W_13
Show-Progress "ISMS-W-14"; Check-ISMS_W_14
Show-Progress "ISMS-W-15"; Check-ISMS_W_15
Show-Progress "ISMS-W-19"; Check-ISMS_W_19
Show-Progress "ISMS-W-21"; Check-ISMS_W_21
Show-Progress "ISMS-W-23"; Check-ISMS_W_23
Show-Progress "ISMS-W-28"; Check-ISMS_W_28
Show-Progress "ISMS-W-29"; Check-ISMS_W_29
Show-Progress "ISMS-W-31"; Check-ISMS_W_31
Show-Progress "ISMS-W-32"; Check-ISMS_W_32
Show-Progress "ISMS-W-33"; Check-ISMS_W_33
Show-Progress "ISMS-W-34"; Check-ISMS_W_34
Show-Progress "ISMS-W-35"; Check-ISMS_W_35
Show-Progress "ISMS-W-36"; Check-ISMS_W_36
Show-Progress "ISMS-W-37"; Check-ISMS_W_37
Show-Progress "ISMS-W-38"; Check-ISMS_W_38
Show-Progress "ISMS-W-40"; Check-ISMS_W_40
Show-Progress "ISMS-W-41"; Check-ISMS_W_41
Show-Progress "ISMS-W-42"; Check-ISMS_W_42
Show-Progress "ISMS-W-43"; Check-ISMS_W_43
Show-Progress "ISMS-W-47"; Check-ISMS_W_47
Show-Progress "ISMS-W-54"; Check-ISMS_W_54
Show-Progress "ISMS-W-55"; Check-ISMS_W_55
Show-Progress "ISMS-W-56"; Check-ISMS_W_56
Show-Progress "ISMS-W-57"; Check-ISMS_W_57
Show-Progress "ISMS-W-58"; Check-ISMS_W_58
Show-Progress "ISMS-W-59"; Check-ISMS_W_59
Show-Progress "ISMS-W-60"; Check-ISMS_W_60
Show-Progress "ISMS-W-61"; Check-ISMS_W_61
Show-Progress "ISMS-W-62"; Check-ISMS_W_62
Show-Progress "ISMS-W-63"; Check-ISMS_W_63
Show-Progress "ISMS-W-64"; Check-ISMS_W_64


Write-Progress -Activity "CCE 취약점 진단" -Completed

###############################################################################
# Generate JSON output
###############################################################################

$scanInfo = [PSCustomObject]@{
    hostname      = $env:COMPUTERNAME
    os            = (Get-CimInstance Win32_OperatingSystem).Caption
    kernel        = [System.Environment]::OSVersion.Version.ToString()
    ip            = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike "*Loopback*" } | Select-Object -First 1).IPAddress
    scan_date     = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    platform      = "Windows"
    guide_sources = @(
        "주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)",
        "클라우드 취약점 점검 가이드 (2024)"
    )
}

$goodCount = ($script:results | Where-Object { $_.status -eq "양호" }).Count
$vulnCount = ($script:results | Where-Object { $_.status -eq "취약" }).Count
$naCount = ($script:results | Where-Object { $_.status -eq "N/A" }).Count
$manualCount = ($script:results | Where-Object { $_.status -eq "수동점검" }).Count

$summary = [PSCustomObject]@{
    total    = $script:results.Count
    "양호"   = $goodCount
    "취약"   = $vulnCount
    "N/A"    = $naCount
    "수동점검" = $manualCount
}

$output = [PSCustomObject]@{
    scan_info = $scanInfo
    summary   = $summary
    results   = $script:results
}

$output | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputFile -Encoding UTF8

Write-Host ""
Write-Host "===== Windows CCE 취약점 진단 완료 =====" -ForegroundColor Cyan
Write-Host ""
Write-Host "결과 요약:" -ForegroundColor Yellow
Write-Host "  총 점검 항목: $($script:results.Count)"
Write-Host "  양호: $goodCount" -ForegroundColor Green
Write-Host "  취약: $vulnCount" -ForegroundColor Red
Write-Host "  N/A: $naCount" -ForegroundColor Gray
Write-Host "  수동점검: $manualCount" -ForegroundColor Yellow
Write-Host ""
Write-Host "결과 파일: $OutputFile"
