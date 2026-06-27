Set-Location $PSScriptRoot

if ($IsWindows -or $ENV:OS) {
    # is Windows
    $exe_suffix = ".exe"
}

if (-not $(Test-Path "./allocfail$exe_suffix" -PathType Leaf)) {
    exit 99 # Hard failure.
}

# 2>&1 here make command fail, use workaround in https://stackoverflow.com/a/12866669
$allocs = $(Invoke-Expression "./allocfail$exe_suffix 2>&1" | ForEach-Object {"$_"})
if ("$allocs" -eq "") {
    exit 99 # Hard failure.
}

Write-Output "allocs: $allocs"

$step = 1
$i = 1
$passes = 
$prev_status = -1
while ($i -le $allocs) {
    Invoke-Expression "./allocfail$exe_suffix $i >`$null 2>&1" | ForEach-Object {"$_"}
    if ($LastExitCode -gt 1) {
        Write-Output "Unallowed fail found: $i"
        exit 1 # Failure.
    }

    # The test-case would run too long if we would excercise all allocs.
    # So, run with step 1 initially, and increase the step once we have 10
    # subsequent passes, and drop back to step 1 once we encounter another
    # failure.  This takes ~2.6 seconds on an i7-6600U CPU @ 2.60GHz.
    if ($status -eq 0) {
        $passes = $passes + 1
        if ($passes -ge 10) {
            $step = $step * 10
            $passes = 0
        }
    } elseif ($status -eq 1) {
        $passes = 0
        $step = 1
    }

    if ($status -ne $prev_status) {
        Write-Output "Status changed to $status at $i"
    }
    $prev_status = $status

    $i = $i + $step
}

# Success.
exit 0
