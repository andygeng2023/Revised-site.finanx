const NOW = () => new Date().toISOString();
const API_HEADERS = { "Content-Type": "application/json", "Cache-Control": "no-store" };
const DEFAULT_SYMBOLS = ["AAPL","MSFT","NVDA","AMZN","GOOGL","META","TSLA","AVGO","JPM","LLY","V","WMT","ORCL","COST","NFLX","AMD"];
const MODEL_VERSION = "finanx-adaptive-1.0.0";
const FULL_MODELS = [
  "last-drift","sma-drift","ema-trend","linear-regression","autoregression",
  "arima-difference","momentum-20","mean-reversion","rsi-reversion","macd-trend",
  "bollinger-reversion","vol-adjusted-trend","regime-trend","holt-trend","volume-weighted"
];
const HYBRID_GROUPS = [
  ["last-drift","sma-drift"],["ema-trend","macd-trend"],["linear-regression","autoregression"],
  ["arima-difference","holt-trend"],["momentum-20","volume-weighted"],
  ["mean-reversion","bollinger-reversion"],["rsi-reversion","mean-reversion"],
  ["vol-adjusted-trend","regime-trend"],["sma-drift","linear-regression","ema-trend"],
  ["autoregression","arima-difference","holt-trend"]
];
const META_GROUPS = [
  ["hybrid-01","hybrid-02","hybrid-03","hybrid-04"],
  ["hybrid-05","hybrid-06","hybrid-07"],
  ["hybrid-08","hybrid-09","hybrid-10"]
];
const MODEL_ARCHITECTURE = { original: 15, hybrid: 10, meta_hybrid: 3, primary_hybrid: 1, total: 29 };

function response(body, status = 200, extra = {}) {
  return new Response(JSON.stringify(body), { status, headers: { ...API_HEADERS, ...extra } });
}
function parseJson(value, fallback = null) {
  try { return typeof value === "string" ? JSON.parse(value) : value; } catch { return fallback; }
}
function validTicker(ticker) { return /^[A-Z0-9.^=-]{1,20}$/.test(String(ticker || "")); }
function clamp(value, min, max) { return Math.min(max, Math.max(min, Number.isFinite(value) ? value : 0)); }
function mean(values) { return values.length ? values.reduce((a,b)=>a+b,0)/values.length : 0; }
function variance(values) { const m=mean(values); return values.length ? mean(values.map(v=>(v-m)*(v-m))) : 0; }
function stdev(values) { return Math.sqrt(Math.max(0,variance(values))); }
function median(values) { if(!values.length)return 0; const x=[...values].sort((a,b)=>a-b); const m=Math.floor(x.length/2); return x.length%2?x[m]:(x[m-1]+x[m])/2; }
function ema(values, period) { if(!values.length)return 0; const k=2/(period+1); let v=values[0]; for(let i=1;i<values.length;i++)v=values[i]*k+v*(1-k); return v; }
function linearSlope(values) {
  const n=values.length;if(n<2)return 0;
  const xMean=(n-1)/2,yMean=mean(values);let num=0,den=0;
  for(let i=0;i<n;i++){num+=(i-xMean)*(values[i]-yMean);den+=(i-xMean)*(i-xMean);}
  return den?num/den:0;
}
function futureTradingDates(lastDate,count) {
  const out=[];const d=new Date(lastDate);
  while(out.length<count){d.setUTCDate(d.getUTCDate()+1);const day=d.getUTCDay();if(day!==0&&day!==6)out.push(d.toISOString().slice(0,10));}
  return out;
}
function calcRsi(closes, period=14) {
  if(closes.length<period+2)return 50;
  const changes=[];for(let i=1;i<closes.length;i++)changes.push(closes[i]-closes[i-1]);
  const tail=changes.slice(-period);const gains=tail.filter(x=>x>0),losses=tail.filter(x=>x<0).map(Math.abs);
  const avgGain=mean(gains)*gains.length/period,avgLoss=mean(losses)*losses.length/period;
  if(!avgLoss)return avgGain?100:50;
  return 100-(100/(1+avgGain/avgLoss));
}
function getOriginalPredictions(closes, volumes) {
  const n=closes.length, returns=[];
  for(let i=1;i<n;i++)if(closes[i]>0&&closes[i-1]>0)returns.push(Math.log(closes[i]/closes[i-1]));
  const tail=returns.slice(-120), short=returns.slice(-20), recentCloses=closes.slice(-60);
  const mu=mean(tail), vol=stdev(tail), last=tail.at(-1)||0;
  const sma20=mean(closes.slice(-20)), sma60=mean(closes.slice(-60));
  const rsi=calcRsi(closes), macd=ema(closes.slice(-60),12)-ema(closes.slice(-60),26);
  const price=closes.at(-1)||1, z20=(price-sma20)/(stdev(closes.slice(-20))||1);
  const regression=linearSlope(recentCloses.map(x=>Math.log(Math.max(x,0.0001))));
  const volRecent=mean(volumes.slice(-20)),volBase=mean(volumes.slice(-60))||1;
  const phi = tail.length>4 ? (()=>{const a=tail.slice(0,-1),b=tail.slice(1);const am=mean(a),bm=mean(b);let num=0,den=0;for(let i=0;i<a.length;i++){num+=(a[i]-am)*(b[i]-bm);den+=(a[i]-am)**2;}return den?clamp(num/den,-0.8,0.8):0;})() : 0;
  const shortMean=mean(short);
  const momentum20=closes.length>21?Math.log(price/closes.at(-21))/20:mu;
  const rsiSignal=clamp((50-rsi)/50*0.0025,-0.006,0.006);
  const trend=clamp(regression,-0.025,0.025);
  const macdSignal=clamp((macd/price)*0.035,-0.008,0.008);
  const predictions={
    "last-drift":mean(returns.slice(-5)),
    "sma-drift":mean(short),
    "ema-trend":ema(returns.slice(-40),12),
    "linear-regression":trend,
    "autoregression":mu+phi*(last-mu),
    "arima-difference":mean(short.map((v,i)=>i? v-short[i-1]:0))*0.25+mu*0.75,
    "momentum-20":momentum20,
    "mean-reversion":clamp((sma20/price-1)*0.055,-0.006,0.006),
    "rsi-reversion":rsiSignal,
    "macd-trend":macdSignal,
    "bollinger-reversion":clamp(-z20*vol*0.16,-0.006,0.006),
    "vol-adjusted-trend":trend/(1+vol*18),
    "regime-trend":clamp((price>sma60?1:-0.45)*Math.abs(shortMean),-0.006,0.006),
    "holt-trend":clamp(ema(returns.slice(-60),20)*0.65+trend*0.35,-0.012,0.012),
    "volume-weighted":shortMean*clamp(volRecent/volBase,0.4,1.8)
  };
  for(const key of Object.keys(predictions))predictions[key]=clamp(predictions[key],-0.035,0.035);
  return { predictions, volatility:vol, rsi, macd:macdSignal, momentum:momentum20 };
}
function weightedMean(entries, weights) {
  let sum=0,total=0;
  for(const key of entries){const value=weights[key]??1;sum+=value;total+=value;}
  if(!total)return 0;
  return mean(entries.map((key)=>0)); // keeps the helper side-effect free; actual values are below
}
function ensemblePredictions(original, globalWeights, full) {
  const candidates={...original};
  const baseKeys=full?FULL_MODELS:["last-drift","sma-drift","ema-trend","linear-regression","momentum-20","mean-reversion","rsi-reversion"];
  const perf=globalWeights||{};
  const w=(key)=>clamp(Number(perf[key]?.weight??1),0.55,1.55);
  for(let i=0;i<HYBRID_GROUPS.length;i++){
    const keys=HYBRID_GROUPS[i].filter(k=>original[k]!==undefined);
    if(!keys.length)continue;
    const den=keys.reduce((a,k)=>a+w(k),0)||1;
    candidates["hybrid-"+String(i+1).padStart(2,"0")]=keys.reduce((a,k)=>a+original[k]*w(k),0)/den;
  }
  for(let i=0;i<META_GROUPS.length;i++){
    const keys=META_GROUPS[i].filter(k=>candidates[k]!==undefined);
    const den=keys.reduce((a,k)=>a+w(k),0)||1;
    candidates["meta-"+String(i+1).padStart(2,"0")]=keys.reduce((a,k)=>a+candidates[k]*w(k),0)/den;
  }
  const metaKeys=["meta-01","meta-02","meta-03"].filter(k=>candidates[k]!==undefined);
  const den=metaKeys.reduce((a,k)=>a+w(k),0)||1;
  candidates.primary=metaKeys.reduce((a,k)=>a+candidates[k]*w(k),0)/den;
  if(!full){
    for(const key of Object.keys(candidates)){
      const allowed=baseKeys.includes(key)||key.startsWith("hybrid-")||key.startsWith("meta-")||key==="primary";
      if(!allowed)delete candidates[key];
    }
  }
  return candidates;
}
function directionAccuracy(predicted, actual) {
  if(Math.abs(actual)<0.00015)return null;
  return (predicted>=0)===(actual>=0)?1:0;
}
async function loadGlobalWeights(db) {
  const rows=await db.prepare("SELECT model_key,observations,correct,accuracy,weight FROM model_learning_state").all();
  return Object.fromEntries(rows.results.map(r=>[r.model_key,r]));
}
async function buildModelEvaluation(closes,volumes,globalWeights,full) {
  const candidatesByKey={}, windows=[];
  const start=Math.max(70,closes.length-110);
  for(let i=start;i<closes.length-1;i++){
    const c=closes.slice(0,i+1),v=volumes.slice(0,i+1);
    const orig=getOriginalPredictions(c,v).predictions;
    const all=ensemblePredictions(orig,globalWeights,full);
    const actual=Math.log(closes[i+1]/closes[i]);
    windows.push({actual,all});
    for(const [key,pred] of Object.entries(all)){
      if(!candidatesByKey[key])candidatesByKey[key]={observations:0,correct:0};
      const hit=directionAccuracy(pred,actual);
      if(hit!==null){candidatesByKey[key].observations++;candidatesByKey[key].correct+=hit;}
    }
  }
  return { stats:Object.fromEntries(Object.entries(candidatesByKey).map(([k,v])=>[k,{...v,accuracy:v.observations?v.correct/v.observations:0.5}])), windows };
}
async function updateGlobalLearning(db,stats) {
  const updated=NOW();
  const statements=Object.entries(stats).filter(([,s])=>s.observations>0).map(([key,s])=>{
    const accuracy=s.accuracy,weight=clamp(0.55+(accuracy-0.5)*1.4,0.55,1.55);
    return db.prepare("INSERT INTO model_learning_state(model_key,observations,correct,accuracy,weight,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(model_key) DO UPDATE SET observations=model_learning_state.observations+excluded.observations,correct=model_learning_state.correct+excluded.correct,accuracy=CAST(model_learning_state.correct+excluded.correct AS REAL)/(model_learning_state.observations+excluded.observations),weight=MIN(1.55,MAX(0.55,0.55+(CAST(model_learning_state.correct+excluded.correct AS REAL)/(model_learning_state.observations+excluded.observations)-0.5)*1.4)),updated_at=excluded.updated_at")
      .bind(key,s.observations,s.correct,accuracy,weight,updated);
  });
  if(statements.length)await db.batch(statements);
}
async function fetchYahoo(ticker,range) {
  const urls=[
    "https://query1.finance.yahoo.com/v8/finance/chart/"+encodeURIComponent(ticker)+"?range="+range+"&interval=1d&events=div%2Csplits",
    "https://query2.finance.yahoo.com/v8/finance/chart/"+encodeURIComponent(ticker)+"?range="+range+"&interval=1d&events=div%2Csplits"
  ];
  let lastError;
  for(const url of urls){
    try{
      const res=await fetch(url,{headers:{"User-Agent":"Mozilla/5.0 (compatible; Finanx/1.0)","Accept":"application/json"}});
      if(!res.ok)throw new Error("Market data provider returned "+res.status);
      const raw=await res.json(),chart=raw?.chart?.result?.[0];
      if(raw?.chart?.error||!chart)throw new Error(raw?.chart?.error?.description||"No market data returned.");
      const quote=chart.indicators?.quote?.[0]||{},adj=chart.indicators?.adjclose?.[0]?.adjclose||[];
      const points=[];
      for(let i=0;i<(chart.timestamp||[]).length;i++){
        const close=Number(adj[i]??quote.close?.[i]),date=chart.timestamp[i];
        if(Number.isFinite(close)&&close>0)points.push({date:new Date(date*1000).toISOString().slice(0,10),close,open:Number(quote.open?.[i])||null,high:Number(quote.high?.[i])||null,low:Number(quote.low?.[i])||null,volume:Number(quote.volume?.[i])||0});
      }
      if(points.length<80)throw new Error("Not enough clean historical observations for analysis.");
      const meta=chart.meta||{};
      return {ticker,company:meta.longName||meta.shortName||ticker,currency:meta.currency||"USD",exchange:meta.exchangeName||"",regularMarketPrice:Number(meta.regularMarketPrice)||points.at(-1).close,previousClose:Number(meta.chartPreviousClose)||points.at(-2).close,as_of:meta.regularMarketTime?new Date(meta.regularMarketTime*1000).toISOString():new Date().toISOString(),points,provider:"Yahoo Finance",retrieved_at:NOW()};
    }catch(error){lastError=error;}
  }
  throw lastError||new Error("Market data unavailable.");
}
async function quoteCached(ticker,range,env) {
  const row=await env.DB.prepare("SELECT payload,fetched_at FROM market_quotes WHERE ticker=? AND range=?").bind(ticker,range).first();
  if(row&&Date.now()-Date.parse(row.fetched_at)<5*60*1000){
    const cached=parseJson(row.payload);if(cached)return {...cached,cache_hit:true};
  }
  const data=await fetchYahoo(ticker,range);
  await env.DB.prepare("INSERT INTO market_quotes(ticker,range,payload,fetched_at) VALUES(?,?,?,?) ON CONFLICT(ticker,range) DO UPDATE SET payload=excluded.payload,fetched_at=excluded.fetched_at")
    .bind(ticker,range,JSON.stringify(data),NOW()).run();
  return data;
}
async function analyzeOne(ticker,indexer,range,horizon,env,jobId) {
  const data=await quoteCached(ticker,range,env),closes=data.points.map(x=>x.close),volumes=data.points.map(x=>x.volume||0);
  if(closes.length<80)throw new Error("Insufficient history to calculate a reliable model ensemble.");
  const original=getOriginalPredictions(closes,volumes).predictions;
  const global=await loadGlobalWeights(env.DB);
  const full=indexer==="FullIndex";
  const evaluated=await buildModelEvaluation(closes,volumes,global,true);
  await updateGlobalLearning(env.DB,evaluated.stats);
  const candidates=ensemblePredictions(original,global,full);
  const primary=Number(candidates.primary||0);
  const vol=stdev(closes.slice(1).map((x,i)=>Math.log(x/closes[i])));
  const dates=futureTradingDates(data.points.at(-1).date,horizon);
  let predicted=closes.at(-1);
  const forecast=dates.map((date,i)=>{
    const decay=Math.pow(0.965,i),daily=clamp(primary*decay,-0.02,0.02);
    predicted=predicted*Math.exp(daily);
    return {date,close:Number(predicted.toFixed(4))};
  });
  const expected=(forecast.at(-1).close/closes.at(-1)-1)*100;
  const recent=evaluated.windows.slice(-60);
  const primaryHits=recent.filter(w=>directionAccuracy(w.all.primary,w.actual)!==null);
  const accuracy=primaryHits.length?primaryHits.filter(w=>directionAccuracy(w.all.primary,w.actual)===1).length/primaryHits.length:null;
  const dispersion=stdev(Object.values(original));
  const agreement=clamp(1-dispersion/(vol||0.01),0,1);
  const riskScore=clamp(vol*8000+(1-agreement)*45,0,100);
  const output={
    ticker,company:data.company,currency:data.currency,exchange:data.exchange,price:data.regularMarketPrice,
    change_percent:data.previousClose?((data.regularMarketPrice/data.previousClose)-1)*100:null,
    as_of:data.as_of,retrieved_at:data.retrieved_at,provider:data.provider,
    indexer,period:range,horizon,model_version:MODEL_VERSION,
    architecture:full?MODEL_ARCHITECTURE:{original:7,hybrid:10,meta_hybrid:3,primary_hybrid:1,total:21},
    history:{dates:data.points.map(x=>x.date),close:closes,volume:volumes},
    forecast:{dates:forecast.map(x=>x.date),hybrid:forecast.map(x=>x.close),points:forecast,expected_change_percent:Number(expected.toFixed(2)),horizon},
    model:{
      model_version:MODEL_VERSION,primary:"primary",candidates,original_models:original,
      metrics:{backtest:{test_accuracy:accuracy===null?null:Number((accuracy*100).toFixed(1)),observations:primaryHits.length},hybrid:{directional_accuracy:accuracy===null?null:Number((accuracy*100).toFixed(1))}},
      validation:{method:"rolling one-step chronological holdout",observations:primaryHits.length,global_learning_observations:Object.values(global).reduce((a,b)=>a+Number(b.observations||0),0)},
      global_weights:Object.fromEntries(Object.entries(global).map(([k,v])=>[k,{accuracy:Number(v.accuracy||0.5),weight:Number(v.weight||1)}]))
    },
    risk:{score:Number(riskScore.toFixed(1)),annualised_volatility:Number((vol*Math.sqrt(252)*100).toFixed(1)),label:riskScore>65?"High":riskScore>35?"Moderate":"Lower"},
    market_summary:{return_1m:closes.length>21?(closes.at(-1)/closes.at(-21)-1)*100:null,return_3m:closes.length>63?(closes.at(-1)/closes.at(-63)-1)*100:null},
    diagnostics:{data_points:closes.length,missing_values_removed:true,adjusted_close_used:true,confidence:Number((agreement*100).toFixed(1))}
  };
  const historyMax=full?1200:600;
  if(output.history.close.length>historyMax){
    const indices=Array.from({length:historyMax},(_,i)=>Math.round(i*(output.history.close.length-1)/(historyMax-1)));
    output.history={dates:indices.map(i=>output.history.dates[i]),close:indices.map(i=>output.history.close[i]),volume:indices.map(i=>output.history.volume[i])};
  }
  return output;
}
async function setJob(db,id,status,progress,stage,extra={}) {
  const fields=["status=?","progress=?","stage=?","updated_at=?"];
  const values=[status,progress,stage,NOW()];
  if(Object.hasOwn(extra,"result")){fields.push("result=?");values.push(JSON.stringify(extra.result));}
  if(Object.hasOwn(extra,"error")){fields.push("error=?");values.push(extra.error);}
  fields.push("attempts=attempts+?");
  values.push(extra.incrementAttempts?1:0);
  values.push(id);
  await db.prepare("UPDATE analysis_jobs SET "+fields.join(",")+" WHERE id=?").bind(...values).run();
}
async function createIndexJob(ticker,indexer,env) {
  const full=indexer==="FullIndex",range=full?"10y":"5y",maxAge=full?24:6;
  const existing=await env.DB.prepare("SELECT indexed_at FROM market_index WHERE ticker=? AND period=? AND horizon=30 AND indexer=?").bind(ticker,range,30,indexer).first();
  if(existing&&Date.now()-Date.parse(existing.indexed_at)<maxAge*3600000)return null;
  const active=await env.DB.prepare("SELECT id FROM analysis_jobs WHERE ticker=? AND period=? AND horizon=30 AND save_to_indexer=? AND status IN ('queued','running') LIMIT 1").bind(ticker,range,indexer).first();
  if(active)return null;
  const id=crypto.randomUUID(),at=NOW();
  await env.DB.prepare("INSERT INTO analysis_jobs(id,ticker,period,horizon,job_type,scan_source,save_to_indexer,status,created_at,updated_at,progress,stage) VALUES(?,?,?,?,?,'both',?,'queued',?,?,0,'Queued for shared indexing')")
    .bind(id,ticker,range,30,"analysis",indexer,at,at).run();
  await env.JOBS.send({id,ticker,indexer,range,horizon:30,type:"analysis"});
  return id;
}
async function processJob(message,env) {
  const id=String(message.id||"");
  const row=await env.DB.prepare("SELECT * FROM analysis_jobs WHERE id=?").bind(id).first();
  if(!row)throw new Error("Analysis job not found.");
  if(row.status==="completed")return;
  if(row.status==="running"&&Date.now()-Date.parse(row.updated_at)<20*60*1000)throw new Error("Job is already being processed.");
  await setJob(env.DB,id,"running",5,"Fetching and validating market history",{incrementAttempts:true});
  try{
    if(row.job_type==="scan"||message.type==="scan"){
      const results=[];
      for(let i=0;i<DEFAULT_SYMBOLS.length;i++){
        const ticker=DEFAULT_SYMBOLS[i];
        await setJob(env.DB,id,"running",10+Math.round(i/DEFAULT_SYMBOLS.length*80),"Scanning "+ticker);
        try{
          const result=await analyzeOne(ticker,"previewIndex","5y",30,env,id);
          results.push({ticker,company:result.company,price:result.price,change_percent:result.change_percent,expected_change_percent:result.forecast.expected_change_percent,risk_score:result.risk.score,directional_accuracy:result.model.metrics.backtest.test_accuracy,history_preview:result.history.close.slice(-60),forecast_preview:result.forecast.hybrid});
        }catch(error){console.warn("Scan skipped "+ticker,error);}
      }
      results.sort((a,b)=>(b.expected_change_percent??-Infinity)-(a.expected_change_percent??-Infinity));
      const result={as_of:NOW(),results:results.slice(0,12),universe:DEFAULT_SYMBOLS.length,model_version:MODEL_VERSION};
      await setJob(env.DB,id,"completed",100,"Market scan complete",{result});
      return;
    }
    const indexer=row.save_to_indexer==="FullIndex"?"FullIndex":"PreviewIndex";
    const range=indexer==="FullIndex"?"10y":"5y";
    await setJob(env.DB,id,"running",35,"Training and validating model candidates");
    const result=await analyzeOne(row.ticker,indexer,range,Number(row.horizon||30),env,id);
    await setJob(env.DB,id,"running",85,"Publishing shared indexed result");
    if(indexer!=="none"){
      await env.DB.prepare("INSERT INTO market_index(ticker,period,horizon,indexer,indexed_at,source_job_id,result,market_cap,avg_dollar_volume) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(ticker,period,horizon,indexer) DO UPDATE SET indexed_at=excluded.indexed_at,source_job_id=excluded.source_job_id,result=excluded.result,market_cap=excluded.market_cap,avg_dollar_volume=excluded.avg_dollar_volume")
        .bind(row.ticker,range,Number(row.horizon||30),indexer,NOW(),id,JSON.stringify(result),null,null).run();
      await env.DB.prepare("INSERT INTO ticker_catalog(ticker,company,currency,last_indexed_at) VALUES(?,?,?,?) ON CONFLICT(ticker) DO UPDATE SET company=excluded.company,currency=excluded.currency,last_indexed_at=excluded.last_indexed_at")
        .bind(row.ticker,result.company,result.currency,NOW()).run();
    }
    await setJob(env.DB,id,"completed",100,"Analysis complete",{result});
  }catch(error){
    const msg=String(error?.message||error).slice(0,400);
    await setJob(env.DB,id,"failed",0,"Analysis failed",{error:msg});
    throw error;
  }
}
async function userFor(req,env) {
  const token=(req.headers.get("Authorization")||"").replace(/^Bearer\s+/i,"");
  if(!token)return null;
  const hash=await sha256(token),at=NOW();
  return env.DB.prepare("SELECT u.id,u.email,u.display_name,u.created_at,u.last_sign_in_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?").bind(hash,at).first();
}
async function sha256(s) {
  const digest=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(s));
  return Array.from(new Uint8Array(digest)).map(x=>x.toString(16).padStart(2,"0")).join("");
}
async function passwordHash(password,salt) {
  const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(password),"PBKDF2",false,["deriveBits"]);
  const bytes=Uint8Array.from(salt.match(/.{2}/g).map(x=>parseInt(x,16)));
  const bits=await crypto.subtle.deriveBits({name:"PBKDF2",salt:bytes,iterations:310000,hash:"SHA-256"},key,256);
  return Array.from(new Uint8Array(bits)).map(x=>x.toString(16).padStart(2,"0")).join("");
}
function randomToken() {
  const bytes=crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
}
async function rateLimit(req,env,bucket,limit,windowMs) {
  const ip=req.headers.get("CF-Connecting-IP")||"unknown",key=await sha256(bucket+":"+ip),now=Date.now(),cutoff=now-windowMs;
  const row=await env.DB.prepare("INSERT INTO api_rate_limits(bucket_key,window_start,attempts) VALUES(?,?,1) ON CONFLICT(bucket_key) DO UPDATE SET attempts=CASE WHEN window_start<=? THEN 1 ELSE attempts+1 END,window_start=CASE WHEN window_start<=? THEN ? ELSE window_start END RETURNING attempts").bind(key,now,cutoff,cutoff,now).first();
  return Number(row?.attempts||0)<=limit;
}
async function authApi(req,env,url) {
  const action=url.pathname.split("/").pop(),body=req.method==="POST"||req.method==="PATCH"?await req.json().catch(()=>({})): {};
  if(["signup","login"].includes(action)&&!await rateLimit(req,env,"auth-"+action,action==="login"?12:5,3600000))return response({error:"Too many attempts. Please wait and try again."},429);
  if(action==="signup"&&req.method==="POST"){
    const email=String(body.email||"").trim().toLowerCase(),password=String(body.password||"");
    if(!/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(email)||password.length<8||password.length>256)return response({error:"Enter a valid email and a password of at least 8 characters."},400);
    const salt=Array.from(crypto.getRandomValues(new Uint8Array(16))).map(x=>x.toString(16).padStart(2,"0")).join("");
    const hash=await passwordHash(password,salt),id=crypto.randomUUID(),at=NOW();
    try{await env.DB.prepare("INSERT INTO users(id,email,password_hash,password_salt,created_at,last_sign_in_at) VALUES(?,?,?,?,?,?)").bind(id,email,hash,salt,at,at).run();}
    catch{return response({error:"An account with that email already exists."},409);}
    const token=randomToken(),expiry=new Date(Date.now()+30*86400000).toISOString();
    await env.DB.prepare("INSERT INTO sessions(token_hash,user_id,created_at,expires_at) VALUES(?,?,?,?)").bind(await sha256(token),id,at,expiry).run();
    return response({user:{id,email,display_name:""},session:{access_token:token,token_type:"bearer",expires_at:Math.floor(Date.now()/1000)+2592000,user:{id,email}}},201);
  }
  if(action==="login"&&req.method==="POST"){
    const email=String(body.email||"").trim().toLowerCase(),password=String(body.password||"");
    const user=await env.DB.prepare("SELECT * FROM users WHERE email=? COLLATE NOCASE").bind(email).first();
    if(!user||await passwordHash(password,user.password_salt)!==user.password_hash)return response({error:"Email or password is incorrect."},401);
    const at=NOW(),token=randomToken(),expiry=new Date(Date.now()+30*86400000).toISOString();
    await env.DB.prepare("UPDATE users SET last_sign_in_at=? WHERE id=?").bind(at,user.id).run();
    await env.DB.prepare("INSERT INTO sessions(token_hash,user_id,created_at,expires_at) VALUES(?,?,?,?)").bind(await sha256(token),user.id,at,expiry).run();
    return response({user:{id:user.id,email:user.email,display_name:user.display_name},session:{access_token:token,token_type:"bearer",expires_at:Math.floor(Date.now()/1000)+2592000,user:{id:user.id,email:user.email}}});
  }
  if(action==="me"&&req.method==="GET"){
    const user=await userFor(req,env);return user?response({user}):response({error:"Sign in again."},401);
  }
  if(action==="logout"&&req.method==="POST"){
    const token=(req.headers.get("Authorization")||"").replace(/^Bearer\s+/i,"");
    if(token)await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await sha256(token)).run();
    return response({success:true});
  }
  if(action==="profile"&&req.method==="PATCH"){
    const user=await userFor(req,env);if(!user)return response({error:"Sign in again."},401);
    if(body.email)return response({error:"Email changes are not enabled in this deployment."},400);
    await env.DB.prepare("UPDATE users SET display_name=? WHERE id=?").bind(String(body.display_name||"").slice(0,80),user.id).run();
    return response({user:{...user,display_name:String(body.display_name||"").slice(0,80)}});
  }
  if(action==="password"&&req.method==="PATCH"){
    const user=await userFor(req,env);if(!user)return response({error:"Sign in again."},401);
    const password=String(body.password||"");if(password.length<8||password.length>256)return response({error:"Password must be at least 8 characters."},400);
    const salt=Array.from(crypto.getRandomValues(new Uint8Array(16))).map(x=>x.toString(16).padStart(2,"0")).join("");
    await env.DB.prepare("UPDATE users SET password_hash=?,password_salt=? WHERE id=?").bind(await passwordHash(password,salt),salt,user.id).run();
    return response({success:true});
  }
  return response({error:"Not found."},404);
}
async function marketSearch(q) {
  const url=new URL("https://query1.finance.yahoo.com/v1/finance/search");url.searchParams.set("q",q);url.searchParams.set("quotesCount","12");url.searchParams.set("newsCount","0");
  const res=await fetch(url,{headers:{"User-Agent":"Mozilla/5.0 (compatible; Finanx/1.0)"}});
  if(!res.ok)throw new Error("Search provider unavailable ("+res.status+").");
  const data=await res.json();
  return (data.quotes||[]).filter(q=>q.symbol&&["EQUITY","ETF","MUTUALFUND","INDEX"].includes(q.quoteType)).map(q=>({ticker:q.symbol,company:q.shortname||q.longname||q.symbol,exchange:q.exchange||"",type:q.quoteType||"EQUITY"}));
}
async function marketFeed(env) {
  const symbols=DEFAULT_SYMBOLS;
  const items=await Promise.all(symbols.map(async ticker=>{
    const row=await env.DB.prepare("SELECT result,indexer,indexed_at FROM market_index WHERE ticker=? ORDER BY CASE WHEN indexer='FullIndex' THEN 0 ELSE 1 END,indexed_at DESC LIMIT 1").bind(ticker).first();
    const cached=parseJson(row?.result);
    if(cached){
      return {ticker,company:cached.company||ticker,price:cached.price??null,change_percent:cached.change_percent??null,currency:cached.currency||"USD",indexer:row.indexer,indexed_at:row.indexed_at,history_preview:cached.history?.close?.slice(-90)||[],forecast_preview:cached.forecast?.hybrid||[],expected_change_percent:cached.forecast?.expected_change_percent??null,risk_score:cached.risk?.score??null};
    }
    try{
      const q=await quoteCached(ticker,"5d",env),p=q.points;
      return {ticker,company:q.company,price:q.regularMarketPrice,change_percent:q.previousClose?100*(q.regularMarketPrice/q.previousClose-1):null,currency:q.currency,indexer:null,indexed_at:null,history_preview:p.map(x=>x.close),forecast_preview:[],expected_change_percent:null,risk_score:null};
    }catch{return {ticker,company:ticker,price:null,change_percent:null,currency:null,indexer:null,indexed_at:null,history_preview:[],forecast_preview:[],expected_change_percent:null,risk_score:null};}
  }));
  return {items,generated_at:NOW(),mode:"shared-index"};
}
async function handleApi(req,env,url) {
  if(req.method==="OPTIONS")return new Response(null,{status:204,headers:{"Access-Control-Allow-Origin":"*","Access-Control-Allow-Headers":"authorization,content-type","Access-Control-Allow-Methods":"GET,POST,PATCH,OPTIONS"}});
  const path=url.pathname;
  if(path==="/api/health"){
    try{const db=await env.DB.prepare("SELECT COUNT(*) AS n FROM analysis_jobs").first();return response({ok:true,service:"revised-finanx",database:"connected",queued_or_saved_jobs:Number(db?.n||0),queue:"bound",time:NOW()});}
    catch{return response({ok:false,service:"revised-finanx",database:"unavailable"},503);}
  }
  if(path.startsWith("/api/auth/"))return authApi(req,env,url);
  if(path==="/api/market-feed"&&req.method==="GET")return response(await marketFeed(env));
  if(path==="/api/search"&&req.method==="GET"){
    const q=(url.searchParams.get("q")||"").trim().slice(0,60);if(q.length<1)return response({results:[]});
    try{return response({results:await marketSearch(q)});}catch(e){return response({error:e.message,results:[]},503);}
  }
  if(path==="/api/stock-market-data"&&(req.method==="GET"||req.method==="POST")){
    const b=req.method==="POST"?await req.json().catch(()=>({})):{};
    const ticker=String(b.ticker||url.searchParams.get("ticker")||"").trim().toUpperCase();
    const range=String(b.period||url.searchParams.get("period")||"5y");
    if(!validTicker(ticker)||!["1y","2y","5y","10y"].includes(range))return response({error:"Invalid ticker or period."},400);
    try{const data=await quoteCached(ticker,range,env);return response({ticker,company:data.company,currency:data.currency,price:data.regularMarketPrice,as_of:data.as_of,history:data.points,provider:data.provider,retrieved_at:data.retrieved_at});}
    catch(e){return response({error:e.message},503);}
  }
  if(path==="/api/index-availability"&&req.method==="GET"){
    const ticker=String(url.searchParams.get("ticker")||"").trim().toUpperCase();if(!validTicker(ticker))return response({error:"Invalid ticker."},400);
    const rows=await env.DB.prepare("SELECT indexer,indexed_at FROM market_index WHERE ticker=? AND horizon=30").bind(ticker).all();
    const now=Date.now(),indexes=rows.results.filter(r=>now-Date.parse(r.indexed_at)<(r.indexer==="FullIndex"?24:6)*3600000).map(r=>({id:r.indexer,indexed_at:r.indexed_at}));
    return response({ticker,indexes,available:indexes.map(x=>x.id),checked_at:NOW()});
  }
  if(path==="/api/request-analysis"&&req.method==="POST"){
    const body=await req.json().catch(()=>({})),mode=body.mode==="scan"?"scan":"analysis";
    const ticker=mode==="scan"?"SCAN":String(body.ticker||"").trim().toUpperCase();
    const indexer=body.save_to_indexer==="FullIndex"?"FullIndex":"PreviewIndex";
    const range=mode==="scan"?"5y":indexer==="FullIndex"?"10y":"5y";
    const horizon=mode==="scan"?30:Math.round(Number(body.horizon||30));
    if(mode==="analysis"&&!validTicker(ticker))return response({error:"Enter a valid ticker."},400);
    if(horizon<1||horizon>252)return response({error:"Forecast horizon must be between 1 and 252 trading days."},400);
    if(!await rateLimit(req,env,"analysis-request",100,3600000))return response({error:"Analysis request limit reached. Please try again later."},429);
    if(mode==="analysis"&&!body.hard_rescan){
      const row=await env.DB.prepare("SELECT id,indexed_at,result FROM market_index WHERE ticker=? AND period=? AND horizon=? AND indexer=?").bind(ticker,range,horizon,indexer).first();
      const maxAge=indexer==="FullIndex"?24:6;
      if(row&&Date.now()-Date.parse(row.indexed_at)<maxAge*3600000){
        const cached=parseJson(row.result);return response({id:row.id||null,status:"completed",ticker,mode,period:range,horizon,save_to_indexer:indexer,progress:100,stage:"Fresh shared index",cached:true,result:cached},200);
      }
    }
    const active=await env.DB.prepare("SELECT id,status,progress,stage FROM analysis_jobs WHERE ticker=? AND period=? AND horizon=? AND save_to_indexer=? AND status IN ('queued','running') ORDER BY created_at DESC LIMIT 1").bind(ticker,range,horizon,indexer).first();
    if(active)return response({id:active.id,status:active.status,ticker,progress:Number(active.progress||0),stage:active.stage||"Queued",reused:true},202);
    const id=crypto.randomUUID(),at=NOW(),user=await userFor(req,env);
    await env.DB.prepare("INSERT INTO analysis_jobs(id,ticker,period,horizon,job_type,scan_source,save_to_indexer,status,created_at,updated_at,progress,stage,user_id) VALUES(?,?,?,?,?,'both',?,'queued',?,?,0,'Waiting for a Cloudflare worker',?)")
      .bind(id,ticker,range,horizon,mode,indexer,at,at,user?.id||null).run();
    await env.JOBS.send({id,ticker,indexer,range,horizon,type:mode});
    return response({id,status:"queued",ticker,mode,period:range,horizon,save_to_indexer:indexer,progress:0,stage:"Waiting for a Cloudflare worker",worker:"Cloudflare Queues"},202);
  }
  if(path==="/api/analysis-status"&&req.method==="GET"){
    const id=url.searchParams.get("id")||"";if(!/^[0-9a-f-]{36}$/i.test(id))return response({error:"Invalid analysis ID."},400);
    const row=await env.DB.prepare("SELECT id,ticker,status,result,error,created_at,updated_at,progress,stage,attempts,period,horizon,save_to_indexer FROM analysis_jobs WHERE id=?").bind(id).first();
    if(!row)return response({error:"Analysis request not found."},404);
    return response({...row,result:parseJson(row.result),progress:row.status==="completed"?100:Number(row.progress||0)});
  }
  if(path==="/api/watchlist"&&req.method==="POST"){
    const user=await userFor(req,env);if(!user)return response({error:"Sign in to use your watchlist."},401);
    const body=await req.json().catch(()=>({})),action=body.action||"list",ticker=String(body.ticker||"").trim().toUpperCase();
    if(action==="add"){
      if(!validTicker(ticker))return response({error:"Invalid ticker."},400);
      await env.DB.prepare("INSERT OR IGNORE INTO watchlist_items(id,user_id,ticker,created_at) VALUES(?,?,?,?)").bind(crypto.randomUUID(),user.id,ticker,NOW()).run();
    }else if(action==="remove"){
      if(!validTicker(ticker))return response({error:"Invalid ticker."},400);
      await env.DB.prepare("DELETE FROM watchlist_items WHERE user_id=? AND ticker=?").bind(user.id,ticker).run();
    }else if(action!=="list")return response({error:"Unknown watchlist action."},400);
    const rows=await env.DB.prepare("SELECT w.ticker,w.created_at,m.indexer,m.indexed_at,m.result FROM watchlist_items w LEFT JOIN market_index m ON m.ticker=w.ticker AND m.indexer='PreviewIndex' WHERE w.user_id=? ORDER BY w.created_at DESC").bind(user.id).all();
    return response({items:rows.results.map(r=>({ticker:r.ticker,added_at:r.created_at,indexer:r.indexer,indexed_at:r.indexed_at,analysis:parseJson(r.result)}))});
  }
  if(path==="/api/model-learning"&&req.method==="GET"){
    const rows=await env.DB.prepare("SELECT model_key,observations,correct,accuracy,weight,updated_at FROM model_learning_state ORDER BY accuracy DESC").all();
    return response({models:rows.results,updated_at:rows.results.reduce((a,r)=>!a||r.updated_at>a?r.updated_at:a,null),scope:"global"});
  }
  if(path==="/api/queue-status"&&req.method==="GET"){
    const rows=await env.DB.prepare("SELECT status,COUNT(*) AS count FROM analysis_jobs WHERE created_at>? GROUP BY status").bind(new Date(Date.now()-24*3600000).toISOString()).all();
    return response({counts:Object.fromEntries(rows.results.map(r=>[r.status,Number(r.count)])),time:NOW(),provider:"Cloudflare Queues"});
  }
  return response({error:"Endpoint not found."},404);
}
async function refreshMarket(env) {
  for(const ticker of DEFAULT_SYMBOLS){
    await env.DB.prepare("INSERT OR IGNORE INTO ticker_catalog(ticker,company,currency,created_at) VALUES(?,?,?,?)").bind(ticker,ticker,"USD",NOW()).run();
    await createIndexJob(ticker,"PreviewIndex",env);
    const full=await env.DB.prepare("SELECT indexed_at FROM market_index WHERE ticker=? AND indexer='FullIndex'").bind(ticker).first();
    if(!full||Date.now()-Date.parse(full.indexed_at)>24*3600000)await createIndexJob(ticker,"FullIndex",env);
  }
}
export default {
  async fetch(req,env,ctx) {
    const url=new URL(req.url);
    try{
      if(url.pathname.startsWith("/api/"))return await handleApi(req,env,url);
      if(!env.ASSETS)return response({error:"Static assets binding is missing."},503);
      const asset=await env.ASSETS.fetch(req);
      if(asset.status!==404)return asset;
      if(!url.pathname.includes(".")&&req.method==="GET")return env.ASSETS.fetch(new Request(new URL("/index.html",url),req));
      return asset;
    }catch(error){
      console.error("Finanx request failed",error);
      return response({error:"The request could not be completed. Please try again."},500);
    }
  },
  async scheduled(controller,env,ctx) {
    ctx.waitUntil(refreshMarket(env));
  },
  async queue(batch,env) {
    for(const message of batch.messages){
      try{await processJob(message.body,env);message.ack();}
      catch(error){console.error("Queue job failed",message.body?.id,error);message.retry({delaySeconds:Math.min(300,20*(message.attempts||1))});}
    }
  }
};
