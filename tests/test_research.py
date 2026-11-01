import io
import numpy as np
import torch
from research.adaptive import decide,IncrementalDecision
from research.metrics import summarize,clustered_intervals
from research.dataset import session_prefixes
from research.models import PrefixModel
from data_processing.production import read_capture
from tests.test_production import pcap,frame


def test_adaptive_stopping_has_no_future_lookahead_and_fixed16_is_fixed():
    p=np.array([[[.4,.3,.3],[.01,.98,.01],[.01,.01,.98],[.99,.005,.005]]])
    d=decide(p,np.array([32]),.95)
    assert d['packets'][0]==8 and d['prediction'][0]==1
    changed=p.copy();changed[:,2:]=[.99,.005,.005]
    assert decide(changed,np.array([32]),.95)['prediction'][0]==1
    assert decide(p,np.array([3]),.95,fixed=16)['stage_index'][0]==2
    assert decide(p,np.array([3]),.95)['prediction'][0]==-1


def test_incremental_requests_more_context_and_never_revises_accepted_result():
    seen=[]
    def infer(context):
        seen.append(len(context));return [.4,.3,.3] if len(context)<8 else [.01,.98,.01]
    detector=IncrementalDecision(infer)
    for count in range(1,9):detector.observe(list(range(count)))
    assert seen==[4,8] and detector.result['packets']==8
    detector.observe(list(range(32)))
    assert seen==[4,8]
    short=IncrementalDecision(lambda context:[.4,.3,.3])
    assert short.observe([1,2],terminal=True)['prediction']==-1


def test_rejection_is_not_a_correct_attack_prediction_or_a_false_attack_alert():
    decision=dict(prediction=np.array([-1,-1,0,2]),raw_prediction=np.array([0,1,0,2]),
                  probabilities=np.array([[.4,.3,.3],[.3,.4,.3],[.9,.05,.05],[.01,.01,.98]]),packets=np.array([4,8,16,32]))
    m=summarize(np.array([0,1,2,2]),decision)
    assert m['correct_accepted_fraction']==.25
    assert m['benign_false_alert_rate']==0 and m['benign_review_rate']==1
    assert m['attack_accepted_benign_rate']==1/3
    assert clustered_intervals(np.array([0,1,2,2]),decision,['one']*4)['status']=='insufficient_capture_clusters'


def test_research_session_retains_first32_and_snapshots_only_available_packets():
    rows=list(session_prefixes(read_capture(io.BytesIO(pcap([frame(flags=16)]*40))),lambda p:'benign'))
    assert len(rows)==1 and len(rows[0]['packets'])==32
    assert [round(np.expm1(feature[0])) for feature in rows[0]['features']]==[4,8,16,32]
    assert rows[0]['ready']==[3,7,15,31]


def test_both_residual_models_use_variable_matched_prefix_bytes():
    torch.set_num_threads(2)
    for kind in ('1d','2d'):
        model=PrefixModel(kind).eval()
        for k in (4,8,16,32):
            with torch.inference_mode():out=model(torch.zeros(2,k,32))
            assert out.shape==(2,3) and torch.isfinite(out).all()


def test_research_api_is_authenticated_read_only_and_does_not_export_models(tmp_path,monkeypatch):
    import json
    from fastapi import FastAPI,Header,HTTPException
    from fastapi.testclient import TestClient
    from api.research import install_research_routes
    root=tmp_path/'research';folder=root/'runs'/'unit-experiment';folder.mkdir(parents=True)
    (folder/'summary.json').write_text(json.dumps({'status':'running','results':[]}))
    (folder/'frozen-config.json').write_text(json.dumps({'dataset':{'dataset_sha256':'hash'}}))
    (folder/'results.csv').write_text('model,score\nunit,0\n')
    (folder/'private.pth').write_text('not-exportable')
    monkeypatch.setenv('TRAFFICSCAN_RESEARCH_ROOT',str(root))
    def authorize(x_api_key:str|None=Header(default=None)):
        if x_api_key!='test-key':raise HTTPException(401,'Key required')
    app=FastAPI();install_research_routes(app,authorize)
    with TestClient(app) as client:
        assert client.get('/api/research/runs').status_code==401
        headers={'X-API-Key':'test-key'}
        assert client.get('/api/research/runs',headers=headers).json()['read_only']
        assert client.get('/api/research/runs/unit-experiment',headers=headers).json()['final'] is None
        assert client.get('/api/research/runs/unit-experiment/files/results.csv',headers=headers).status_code==200
        assert client.get('/api/research/runs/unit-experiment/files/private.pth',headers=headers).status_code==404
        assert client.get('/api/research/runs/bad.id',headers=headers).status_code==422
        assert client.post('/api/research/runs',headers=headers).status_code==405
