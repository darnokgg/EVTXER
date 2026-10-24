# UI Automation helpers for driving EVTXER's real window. Dot-source, then call.
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
$script:AE = [System.Windows.Automation.AutomationElement]
$script:TS = [System.Windows.Automation.TreeScope]

function Get-UiWindow([string]$TitleLike = 'EVTXER*', [int]$TimeoutSec = 60) {
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        $all = $script:AE::RootElement.FindAll($script:TS::Children, [System.Windows.Automation.Condition]::TrueCondition)
        foreach ($w in $all) { if ($w.Current.Name -like $TitleLike) { return $w } }
        Start-Sleep -Milliseconds 500
    }
    throw "no window '$TitleLike'"
}
function Get-Ui($Root, [string]$Id, [int]$TimeoutSec = 10) {
    $cond = New-Object System.Windows.Automation.PropertyCondition($script:AE::AutomationIdProperty, $Id)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        $e = $Root.FindFirst($script:TS::Descendants, $cond)
        if ($e) { return $e }
        Start-Sleep -Milliseconds 300
    }
    throw "no element '$Id'"
}
function Invoke-Ui($Root, [string]$Id) {
    $e = Get-Ui $Root $Id
    $e.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
}
function Get-UiText($Root, [string]$Id) { (Get-Ui $Root $Id).Current.Name }
function Set-UiChecked($Root, [string]$Id, [bool]$On) {
    $e = Get-Ui $Root $Id
    $t = $e.GetCurrentPattern([System.Windows.Automation.TogglePattern]::Pattern)
    if (($t.Current.ToggleState -eq 'On') -ne $On) { $t.Toggle() }
}
function Select-UiTab($Root, [string]$Header) {
    $cond = New-Object System.Windows.Automation.PropertyCondition($script:AE::NameProperty, $Header)
    $e = $Root.FindFirst($script:TS::Descendants, $cond)
    $e.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern).Select()
}
function Get-UiListRows($Root, [string]$Id) {
    # Each row's texts, joined with ' | '.
    $list = Get-Ui $Root $Id
    $items = $list.FindAll($script:TS::Children, [System.Windows.Automation.Condition]::TrueCondition)
    foreach ($it in $items) {
        $texts = $it.FindAll($script:TS::Descendants,
            (New-Object System.Windows.Automation.PropertyCondition($script:AE::ControlTypeProperty, [System.Windows.Automation.ControlType]::Text)))
        (@($texts | ForEach-Object { $_.Current.Name }) -join ' | ')
    }
}
function Select-UiListRow($Root, [string]$Id, [string]$Like) {
    $list = Get-Ui $Root $Id
    foreach ($it in $list.FindAll($script:TS::Children, [System.Windows.Automation.Condition]::TrueCondition)) {
        $texts = @($it.FindAll($script:TS::Descendants, [System.Windows.Automation.Condition]::TrueCondition) | ForEach-Object { $_.Current.Name }) -join ' '
        if ($texts -like $Like) { $it.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern).Select(); return $true }
    }
    return $false
}
function Get-UiOwned($Owner, [string]$TitleLike, [int]$TimeoutSec = 20) {
    $cond = New-Object System.Windows.Automation.PropertyCondition($script:AE::ControlTypeProperty, [System.Windows.Automation.ControlType]::Window)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        foreach ($c in $Owner.FindAll($script:TS::Children, $cond)) { if ($c.Current.Name -like $TitleLike) { return $c } }
        Start-Sleep -Milliseconds 300
    }
    throw "no owned window '$TitleLike'"
}
function Invoke-UiByName($Root, [string]$Name) {
    $cond = New-Object System.Windows.Automation.AndCondition(
        (New-Object System.Windows.Automation.PropertyCondition($script:AE::NameProperty, $Name)),
        (New-Object System.Windows.Automation.PropertyCondition($script:AE::ControlTypeProperty, [System.Windows.Automation.ControlType]::Button)))
    $Root.FindFirst($script:TS::Descendants, $cond).GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
}
function Get-UiWindowByPid([int]$ProcId, [int]$TimeoutSec = 60) {
    # The EVTXER window of one process - when more than one is open.
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        foreach ($c in $script:AE::RootElement.FindAll($script:TS::Children, [System.Windows.Automation.Condition]::TrueCondition)) {
            if ($c.Current.ProcessId -eq $ProcId -and $c.Current.Name -like 'EVTXER*') { return $c }
        }
        Start-Sleep -Milliseconds 500
    }
    throw "no EVTXER window for process $ProcId"
}
