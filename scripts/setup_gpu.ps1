$ErrorActionPreference = 'Stop'
$workspace = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $workspace
$gpuPython = Join-Path $workspace '.venv-gpu/Scripts/python.exe'
$torchWheel = Join-Path $workspace 'artifacts/gpu-wheels/torch-2.14.1+cu130-cp312-cp312-win_amd64.whl'
$trtWheel = Join-Path $workspace 'artifacts/gpu-wheels/tensorrt_cu13_libs-11.4.0.106-py3-none-win_amd64.whl'
$deadline = (Get-Date).AddMinutes(90)
foreach ($wheel in @($torchWheel, $trtWheel)) {
    while (-not (Test-Path -LiteralPath $wheel)) {
        if ((Get-Date) -gt $deadline) { throw 'GPU wheel acquisition deadline exceeded' }
        Start-Sleep -Seconds 5
    }
    & $gpuPython -m pip install --no-index $wheel
    if ($LASTEXITCODE -ne 0) { throw "Wheel installation failed: $wheel" }
}
& $gpuPython -m pip install 'tensorrt-cu13==11.4.0.106' --extra-index-url https://pypi.nvidia.com
if ($LASTEXITCODE -ne 0) { throw 'TensorRT Python bindings installation failed' }
& $gpuPython -c "import json,torch,tensorrt; from pathlib import Path; assert torch.cuda.is_available(); x=torch.ones(64,1,512,device='cuda'); assert x.sum().item()==32768; r=dict(torch=str(torch.__version__),cuda=torch.version.cuda,gpu=torch.cuda.get_device_name(),tensorrt=tensorrt.__version__,cuda_verified=True); Path('artifacts/gpu-setup/runtime.json').write_text(json.dumps(r,indent=2)); print(r)"
if ($LASTEXITCODE -ne 0) { throw 'GPU runtime verification failed' }
