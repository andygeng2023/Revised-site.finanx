import PAGE from "./page.js";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,PATCH,DELETE,OPTIONS",
  "Access-Control-Allow-Headers": "Authorization,Content-Type",
  "Content-Type": "application/json; charset=utf-8"
};
const POPULAR = ["AAPL","MSFT","NVDA","GOOGL","AMZN","META","TSLA","BRK-B","JPM","LLY","AVGO","COST"];
const PREVIEW_VERSION = "finanx-preview-1";
const FULL_VERSION = "finanx-full-1";
const clamp = (n, lo, hi) => Math.max(lo, Math.min(hi, Number.isFinite(n) ? n : 0));
const isoNow = () => new Date().toISOString();
const json = (body,status=200,extra={}) => new Response(JSON.stringify(body),{status,headers:{...CORS,"Cache-Control":"no-store",...extra}});
const parse = value => { try { return typeof value==="string" ? JSON.parse(value) : value; } catch { return null; } };
const validTicker = value => /^[A-Z0-9.^=-]{1,20}$/.test(String(value||""));
const stmt = (env,sql,...args) => env.DB.prepare(sql).bind(...args);
const first = async (env,sql,...args) => stmt(env,sql,...args).first();
const all = async (env,sql,...args) => (await stmt(env,sql,...args).all()).results || [];
const run = async (env,sql,...args) => stmt(env,sql,...args).run();
const hex = bytes => Array.from(new Uint8Array(bytes)).map(x=>x.toString(16).padStart(2,"0")).join("");
const sha = async value => hex(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(value)));
const random = size => { const bytes=crypto.getRandomValues(new Uint8Array(size));return btoa(String.fromCharCode(...bytes)).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,""); };
async function passwordHash(password,salt){
  const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(password),"PBKDF2",false,["deriveBits"]);
  const bits=await crypto.subtle.deriveBits({name:"PBKDF2",salt:new Uint8Array(salt.match(/.{2}/g).map(x=>parseInt(x,16))),iterations:110000,hash:"SHA-256"},key,256);
  return hex(bits);
}
function tokenFrom(req){return (req.headers.get("Authorization")||"").replace(/^Bearer\s+/i,"").trim();}
function userShape(row){return {id:row.id,email:row.email,display_name:row.display_name||"",created_at:row.created_at,last_sign_in_at:row.last_sign_in_at};}
async function createSession(env,userId){
  const token=random(32),now=isoNow(),expires=new Date(Date.now()+30*86400000).toISOString();
  await run(env,"INSERT INTO sessions(token_hash,user_id,created_at,expires_at) VALUES(?,?,?,?)",await sha(token),userId,now,expires);
  return {access_token:token,token_type:"bearer",expires_at:Math.floor(Date.now()/1000)+2592000};
}
async function authUser(req,env){
  const token=tokenFrom(req);if(!token)return null;
  return first(env,"SELECT u.id,u.email,u.display_name,u.created_at,u.last_sign_in_at,s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?",await sha(token),isoNow());
}
async function rateLimit(env,req,key,max,windowMs){
  const ip=(req.headers.get("cf-connecting-ip")||"unknown").slice(0,80),bucket=await sha(key+":"+ip),now=Date.now(),cut=now-windowMs;
  const row=await first(env,"INSERT INTO api_rate_limits(bucket_key,window_start,attempts) VALUES(?,?,1) ON CONFLICT(bucket_key) DO UPDATE SET attempts=CASE WHEN api_rate_limits.window_start<=? THEN 1 ELSE api_rate_limits.attempts+1 END,window_start=CASE WHEN api_rate_limits.window_start<=? THEN ? ELSE api_rate_limits.window_start END RETURNING attempts",bucket,now,cut,cut,now);
  return Number(row?.attempts||0)<=max;
}
async function authRoute(req,env,url){
  const route=url.pathname.split("/").pop(),method=req.method;
  const body=method==="POST"||method==="PATCH"?await req.json().catch(()=>({})): {};
  if(["signup","login"].includes(route)&&!await rateLimit(env,req,"auth-"+route,route==="signup"?5:12,3600000))return json({error:"Too many attempts. Try again later."},429);
  if(route==="signup"&&method==="POST"){
    const email=String(body.email||"").trim().toLowerCase(),password=String(body.password||"");
    if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||password.length<8||password.length>256)return json({error:"Enter a valid email and a password of at least 8 characters."},400);
    const salt=hex(crypto.getRandomValues(new Uint8Array(16))),hash=await passwordHash(password,salt),id=crypto.randomUUID(),created=isoNow();
    try{await run(env,"INSERT INTO users(id,email,password_hash,password_salt,created_at,last_sign_in_at) VALUES(?,?,?,?,?,?)",id,email,hash,salt,created,created);}
    catch{return json({error:"An account with that email already exists."},409);}
    const session=await createSession(env,id),user={id,email,display_name:"",created_at:created,last_sign_in_at:created};
    return json({user,session:{...session,user}},201);
  }
  if(route==="login"&&method==="POST"){
    const email=String(body.email||"").trim().toLowerCase(),password=String(body.password||"");
    const row=await first(env,"SELECT * FROM users WHERE email=? COLLATE NOCASE",email);
    if(!row||await passwordHash(password,row.password_salt)!==row.password_hash)return json({error:"Email or password is incorrect."},401);
    const signed=isoNow();await run(env,"UPDATE users SET last_sign_in_at=? WHERE id=?",signed,row.id);
    const session=await createSession(env,row.id),user=userShape({...row,last_sign_in_at:signed});
    return json({user,session:{...session,user}});
  }
  if(route==="me"&&method==="GET"){
    const user=await authUser(req,env);if(!user)return json({error:"Your session has expired. Sign in again."},401);
    return json({user:userShape(user)});
  }
  if(route==="logout"&&method==="POST"){
    const token=tokenFrom(req);if(token)await run(env,"DELETE FROM sessions WHERE token_hash=?",await sha(token));
    return json({success:true});
  }
  if(route==="password"&&method==="PATCH"){
    const user=await authUser(req,env);if(!user)return json({error:"Sign in again."},401);
    const password=String(body.password||"");if(password.length<8||password.length>256)return json({error:"Password must contain at least 8 characters."},400);
    const salt=hex(crypto.getRandomValues(new Uint8Array(16))),hash=await passwordHash(password,salt);
    await run(env,"UPDATE users SET password_hash=?,password_salt=? WHERE id=?",hash,salt,user.id);
    return json({success:true});
  }
  return json({error:"Not found."},404);
}
async function yahooChart(ticker,period){
  const range=period==="10y"?"10y":period==="max"?"max":"5y";
  const url=new URL("https://query1.finance.yahoo.com/v8/finance/chart/"+encodeURIComponent(ticker));
  url.searchParams.set("range",range);url.searchParams.set("interval","1d");url.searchParams.set("events","div,splits");url.searchParams.set("includeAdjustedClose","true");
  const attempts=[url.toString(),url.toString().replace("query1.finance.yahoo.com","query2.finance.yahoo.com")];
  let lastError=null;
  for(const target of attempts){
    try{
      const response=await fetch(target,{headers:{"User-Agent":"Mozilla/5.0 FinanxResearch/1.0","Accept":"application/json"},signal:AbortSignal.timeout(14000)});
      if(!response.ok)throw new Error("Market data provider returned "+response.status);
      const data=await response.json(),result=data?.chart?.result?.[0];
      if(!result)throw new Error(data?.chart?.error?.description||"No market data returned.");
      const q=result.indicators?.quote?.[0]||{},adj=result.indicators?.adjclose?.[0]?.adjclose||[];
      const rows=(result.timestamp||[]).map((timestamp,i)=>({date:new Date(timestamp*1000).toISOString().slice(0,10),open:q.open?.[i]??null,high:q.high?.[i]??null,low:q.low?.[i]??null,close:adj[i]??q.close?.[i]??null,volume:q.volume?.[i]??null})).filter(x=>Number.isFinite(x.close)&&x.close>0);
      if(rows.length<80)throw new Error("Not enough valid historical prices were returned.");
      const meta=result.meta||{},last=rows.at(-1),previous=rows.at(-2);
      return {ticker,company:meta.longName||meta.shortName||ticker,currency:meta.currency||"USD",exchange:meta.exchangeName||"",exchange_timezone:meta.exchangeTimezoneName||"UTC",price:Number(meta.regularMarketPrice||last.close),change_percent:previous?100*(last.close/previous.close-1):null,as_of:last.date,history:rows,source:"Yahoo Finance chart data"};
    }catch(error){lastError=error;}
  }
  throw lastError||new Error("Market data unavailable.");
}
async function yahooFundamentals(ticker){
  const url=new URL("https://query1.finance.yahoo.com/v10/finance/quoteSummary/"+encodeURIComponent(ticker));
  url.searchParams.set("modules","price,summaryDetail,assetProfile,defaultKeyStatistics,financialData");
  try{
    const response=await fetch(url,{headers:{"User-Agent":"Mozilla/5.0 FinanxResearch/1.0"},signal:AbortSignal.timeout(9000)});
    if(!response.ok)return {};
    const data=await response.json(),item=data?.quoteSummary?.result?.[0]||{};
    const raw=x=>x&&typeof x==="object"&&"raw"in x?x.raw:null;
    return {sector:item.assetProfile?.sector||null,industry:item.assetProfile?.industry||null,market_cap:raw(item.price?.marketCap),trailing_pe:raw(item.summaryDetail?.trailingPE),forward_pe:raw(item.summaryDetail?.forwardPE),profit_margin:raw(item.financialData?.profitMargins),return_on_equity:raw(item.financialData?.returnOnEquity),dividend_yield:raw(item.summaryDetail?.dividendYield),beta:raw(item.defaultKeyStatistics?.beta),employees:item.assetProfile?.fullTimeEmployees||null,website:item.assetProfile?.website||null};
  }catch{return {};}
}
function returnsOf(close){const r=[];for(let i=1;i<close.length;i++)if(close[i-1]>0&&close[i]>0)r.push(close[i]/close[i-1]-1);return r;}
function mean(a){return a.length?a.reduce((s,v)=>s+v,0)/a.length:0;}
function median(a){if(!a.length)return 0;const x=[...a].sort((p,q)=>p-q);return x[Math.floor(x.length/2)];}
function std(a){const m=mean(a);return Math.sqrt(mean(a.map(x=>(x-m)**2)));}
function slope(values){
  const n=values.length;if(n<3)return 0;let sx=0,sy=0,sxx=0,sxy=0;
  values.forEach((v,i)=>{sx+=i;sy+=v;sxx+=i*i;sxy+=i*v;});
  const den=n*sxx-sx*sx;return den?((n*sxy-sx*sy)/den):0;
}
function originalSignals(close){
  const r=returnsOf(close),n=close.length,tail=(a,k)=>a.slice(-k),last=close.at(-1),r5=mean(tail(r,5)),r20=mean(tail(r,20)),r60=mean(tail(r,60)),r120=mean(tail(r,120)),r252=mean(tail(r,252)),vol=std(tail(r,60))||0.01;
  const avg=(k)=>mean(tail(close,k)),s5=avg(5),s20=avg(20),s50=avg(50),s100=avg(100),logTrend=slope(tail(close.map(Math.log),Math.min(n,90)));
  const gains=tail(r,14).filter(x=>x>0),losses=tail(r,14).filter(x=>x<0).map(Math.abs),rs=mean(gains)/(mean(losses)||0.0001),rsi=100-100/(1+rs);
  const max20=Math.max(...tail(close,20)),min20=Math.min(...tail(close,20));
  const centered=(last/(s20||last)-1);
  const raw=[
    r20*0.75,
    mean(tail(r,45))*0.55,
    r5*1.3,
    r20*1.05,
    r60*0.72,
    (s5/(s20||last)-1)*0.55,
    slope(tail(close,40))/last,
    logTrend,
    -centered*0.32,
    (50-rsi)/50*vol*0.35,
    r60/(1+vol*20)*0.9,
    (last>max20*0.995?0.0018:last<min20*1.005?-0.0018:0)+r20*0.25,
    r20-0.25*(r5-r20),
    median(tail(r,35))*1.4,
    (s20/(s100||last)-1)*0.16+r60*0.18
  ];
  const names=["Random Walk Drift","SMA Momentum","Short Momentum","Medium Momentum","Long Momentum","EMA Crossover","Linear Regression","Log Trend","Mean Reversion","RSI Regime","Volatility-Adjusted Momentum","Breakout Trend","AR(1) Return","Robust Median Trend","Long-Term Trend"];
  return {names,signals:raw.map(x=>clamp(x,-0.025,0.025)),volatility:vol,rsi,drawdown:last/Math.max(...tail(close,252))-1,shortAverage:s5,longAverage:s100};
}
function hybridSignals(original){
  const s=original.signals;
  const pairs=[[0,3],[2,5],[3,4],[6,7],[8,9],[10,11],[12,13],[1,14],[5,10],[7,14]];
  const names=["Momentum Blend","Moving-Average Blend","Multi-Horizon Trend","Regression Blend","Mean-Reversion Blend","Risk-Adjusted Blend","Breakout Consensus","Drift Consensus","Technical Composite","Trend Composite"];
  return {names,signals:pairs.map(([a,b])=>0.5*(s[a]+s[b]))};
}
function metaSignals(original,hybrid){
  const h=hybrid.signals;
  return {names:["Meta Consensus","Meta Risk-Adjusted","Meta Regime-Adaptive"],signals:[
    mean(h),
    mean(h.map((x,i)=>x/(1+Math.abs(x)*30))),
    original.volatility>0.025?mean(h.slice(0,5)):mean(h.slice(5))
  ]};
}
function candidateBundle(close){
  const o=originalSignals(close),h=hybridSignals(o),m=metaSignals(o,h);
  return [
    ...o.names.map((name,i)=>({name,type:"Original",signal:o.signals[i]})),
    ...h.names.map((name,i)=>({name,type:"Hybrid",signal:h.signals[i]})),
    ...m.names.map((name,i)=>({name,type:"Meta-hybrid",signal:m.signals[i]}))
  ];
}
function validateChronologically(close){
  const count=close.length,from=Math.max(90,count-70),scores=new Map();
  for(let i=from;i<count-6;i+=3){
    const train=close.slice(0,i),actual=close[i+5]/close[i]-1;
    if(train.length<80)continue;
    const candidates=candidateBundle(train);
    for(const c of candidates){const row=scores.get(c.name)||{observations:0,correct:0};row.observations++;if(Math.sign(c.signal)===Math.sign(actual))row.correct++;scores.set(c.name,row);}
    const primarySignal=mean(candidates.map(c=>c.signal));
    const primary=scores.get("Adaptive Primary Hybrid")||{observations:0,correct:0};
    primary.observations++;
    if(Math.sign(primarySignal)===Math.sign(actual))primary.correct++;
    scores.set("Adaptive Primary Hybrid",primary);
  }
  return scores;
}
async function updateGlobalLearning(env,scoreMap){
  for(const [name,score] of scoreMap){
    if(!score.observations)continue;
    const accuracy=score.correct/score.observations;
    await run(env,"INSERT INTO model_learning_state(model_key,observations,correct,accuracy,weight,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(model_key) DO UPDATE SET observations=model_learning_state.observations+excluded.observations,correct=model_learning_state.correct+excluded.correct,accuracy=CAST(model_learning_state.correct+excluded.correct AS REAL)/(model_learning_state.observations+excluded.observations),weight=MAX(0.25,MIN(2.5,1.0+(CAST(model_learning_state.correct+excluded.correct AS REAL)/(model_learning_state.observations+excluded.observations)-0.5)*2.0)),updated_at=excluded.updated_at",name,score.observations,score.correct,accuracy,clamp(0.8+accuracy,0.5,1.5),isoNow());
  }
}
async function modelWeights(env,candidates,localScores){
  const keys=candidates.map(x=>x.name),rows=keys.length?await all(env,"SELECT model_key,observations,accuracy,weight FROM model_learning_state WHERE model_key IN ("+keys.map(()=>"?").join(",")+")",...keys):[];
  const map=new Map(rows.map(x=>[x.model_key,x]));
  return candidates.map(c=>{
    const global=map.get(c.name),local=localScores.get(c.name);
    const historical=global&&Number(global.observations)>0?Number(global.accuracy):0.5;
    const validation=local?.observations?local.correct/local.observations:historical;
    const weight=clamp(0.35+historical*0.9+validation*0.7,0.45,2.1);
    return {...c,validation_accuracy:validation,observations:Number(global?.observations||0)+(local?.observations||0),weight};
  });
}
async function makeAnalysis(env,job){
  const period=job.save_to_indexer==="FullIndex"?"10y":(job.period||"5y");
  await run(env,"UPDATE analysis_jobs SET status='running',progress=5,stage='Downloading and validating market history',updated_at=? WHERE id=?",isoNow(),job.id);
  const quote=await yahooChart(job.ticker,period);
  const fundamentals=await yahooFundamentals(job.ticker);
  const rows=quote.history,close=rows.map(x=>x.close),horizon=clamp(Number(job.horizon||30),1,504);
  const splitScores=validateChronologically(close);
  await run(env,"UPDATE analysis_jobs SET progress=33,stage='Validating 28 model candidates',updated_at=? WHERE id=?",isoNow(),job.id);
  const candidates=candidateBundle(close),weighted=await modelWeights(env,candidates,splitScores);
  await updateGlobalLearning(env,splitScores);
  const original=weighted.filter(x=>x.type==="Original"),hybrids=weighted.filter(x=>x.type==="Hybrid"),meta=weighted.filter(x=>x.type==="Meta-hybrid");
  const ensemble=job.save_to_indexer==="FullIndex"?weighted:weighted.filter(x=>x.type==="Original").slice(0,7).concat(weighted.filter(x=>x.type==="Hybrid").slice(0,3),weighted.filter(x=>x.type==="Meta-hybrid").slice(0,1));
  const weightSum=ensemble.reduce((s,x)=>s+x.weight,0)||1;
  const dailySignal=ensemble.reduce((s,x)=>s+x.signal*x.weight,0)/weightSum;
  const expected=clamp((Math.pow(1+dailySignal,horizon)-1)*100,-45,60);
  const dailyVol=std(returnsOf(close).slice(-60))||0.018;
  const forecast=[],lower=[],upper=[];
  for(let i=1;i<=horizon;i++){
    const trend=Math.pow(1+dailySignal,i),uncertainty=1.65*dailyVol*Math.sqrt(i);
    forecast.push(Number((close.at(-1)*trend).toFixed(4)));
    lower.push(Number((close.at(-1)*trend*Math.exp(-uncertainty)).toFixed(4)));
    upper.push(Number((close.at(-1)*trend*Math.exp(uncertainty)).toFixed(4)));
  }
  const accuracy=ensemble.map(x=>x.validation_accuracy).reduce((s,x)=>s+x,0)/(ensemble.length||1);
  const risk=clamp(35+dailyVol*1100+Math.max(0,-originalSignals(close).drawdown)*80,0,100);
  const modelVersion=job.save_to_indexer==="FullIndex"?FULL_VERSION:PREVIEW_VERSION;
  const result={
    ticker:job.ticker,company:quote.company,currency:quote.currency,exchange:quote.exchange,price:quote.price,change_percent:quote.change_percent,as_of:quote.as_of,data_source:quote.source,indexed_at:isoNow(),
    history:{period,dates:rows.slice(-2600).map(x=>x.date),close:rows.slice(-2600).map(x=>x.close),volume:rows.slice(-2600).map(x=>x.volume)},
    forecast:{horizon,hybrid:forecast,lower_bound:lower,upper_bound:upper,expected_change_percent:expected,model_name:"Adaptive Primary Hybrid"},
    risk:{score:Number(risk.toFixed(1)),annualized_volatility:Number((dailyVol*Math.sqrt(252)*100).toFixed(2)),recent_drawdown:Number((originalSignals(close).drawdown*100).toFixed(2))},
    model:{version:modelVersion,primary:"Adaptive Primary Hybrid",original_count:15,hybrid_count:10,meta_count:3,metrics:{backtest:{directional_accuracy:Number(accuracy.toFixed(4)),validation_windows:[...splitScores.values()].reduce((s,x)=>s+x.observations,0)}},learning_observations:weighted.reduce((s,x)=>s+x.observations,0)+(splitScores.get("Adaptive Primary Hybrid")?.observations||0),candidates:[...weighted,{name:"Adaptive Primary Hybrid",type:"Primary hybrid",signal:dailySignal,validation_accuracy:splitScores.get("Adaptive Primary Hybrid")?.observations?splitScores.get("Adaptive Primary Hybrid").correct/splitScores.get("Adaptive Primary Hybrid").observations:accuracy,weight:1}]},
    fundamentals:{...fundamentals,source:"Yahoo Finance quote summary"}
  };
  await run(env,"UPDATE analysis_jobs SET progress=72,stage='Building forecasts and model diagnostics',updated_at=? WHERE id=?",isoNow(),job.id);
  return result;
}
async function enqueueJob(env,job){
  await env.ANALYSIS_QUEUE.send({jobId:job.id});
}
async function requestAnalysis(req,env){
  const body=await req.json().catch(()=>({})),ticker=String(body.ticker||"").trim().toUpperCase(),indexer=String(body.save_to_indexer||body.indexer||"PreviewIndex").toLowerCase()==="fullindex"?"FullIndex":"PreviewIndex";
  if(!validTicker(ticker))return json({error:"Enter a valid stock ticker."},400);
  if(!await rateLimit(env,req,"analysis-request",90,3600000))return json({error:"Analysis request limit reached for this connection. Try later."},429);
  const period=indexer==="FullIndex"?"10y":"5y",horizon=clamp(Number(body.horizon||30),1,504),maxAge=indexer==="FullIndex"?24:8,cutoff=new Date(Date.now()-maxAge*3600000).toISOString();
  if(!body.hard_rescan){
    const cached=await first(env,"SELECT result,indexed_at,source_job_id FROM market_index WHERE ticker=? AND period=? AND horizon=? AND indexer=? AND indexed_at>=? LIMIT 1",ticker,period,horizon,indexer,cutoff);
    if(cached?.result)return json({status:"completed",ticker,indexer,cached:true,result:parse(cached.result),id:cached.source_job_id,progress:100,stage:"Loaded shared index"});
  }
  const active=await first(env,"SELECT id,status,progress,stage FROM analysis_jobs WHERE ticker=? AND period=? AND horizon=? AND save_to_indexer=? AND status IN ('queued','running') ORDER BY created_at DESC LIMIT 1",ticker,period,horizon,indexer);
  if(active)return json({...active,ticker,indexer,reused:true},202);
  const user=await authUser(req,env),id=crypto.randomUUID(),created=isoNow();
  await run(env,"INSERT INTO analysis_jobs(id,ticker,period,horizon,job_type,scan_source,save_to_indexer,status,created_at,updated_at,progress,stage,user_id) VALUES(?,?,?,?,'analysis','both',?,'queued',?,?,0,'Waiting for analysis worker',?)",id,ticker,period,horizon,indexer,created,created,user?.id||null);
  try{await enqueueJob(env,{id});}
  catch(error){await run(env,"UPDATE analysis_jobs SET status='failed',error=?,updated_at=?,stage='Could not reach the analysis queue' WHERE id=?",String(error.message||error),isoNow(),id);return json({error:"The analysis queue is temporarily unavailable."},503);}
  return json({id,status:"queued",ticker,indexer,period,horizon,progress:0,stage:"Waiting for analysis worker"},202);
}
async function analysisStatus(url,env){
  const id=url.searchParams.get("id")||"";
  if(!/^[0-9a-f-]{36}$/i.test(id))return json({error:"Invalid job identifier."},400);
  const job=await first(env,"SELECT id,ticker,status,result,error,created_at,updated_at,progress,stage,attempts,period,horizon,save_to_indexer FROM analysis_jobs WHERE id=?",id);
  if(!job)return json({error:"Analysis job not found."},404);
  return json({...job,result:parse(job.result),progress:job.status==="completed"?100:Number(job.progress||0)});
}
async function indexAvailability(url,env){
  const ticker=(url.searchParams.get("ticker")||"").toUpperCase();
  if(!validTicker(ticker))return json({error:"Enter a valid ticker."},400);
  const definitions=[{id:"PreviewIndex",period:"5y",age:8},{id:"FullIndex",period:"10y",age:24}],indexes=[];
  for(const item of definitions){
    const cutoff=new Date(Date.now()-item.age*3600000).toISOString();
    const row=await first(env,"SELECT indexed_at FROM market_index WHERE ticker=? AND period=? AND horizon=30 AND indexer=? AND indexed_at>=?",ticker,item.period,item.id,cutoff);
    if(row)indexes.push({id:item.id,label:item.id,indexed_at:row.indexed_at});
  }
  return json({ticker,indexes,available:indexes.map(x=>x.id),checked_at:isoNow()});
}
async function stockMarketData(url,env){
  const ticker=(url.searchParams.get("ticker")||"").toUpperCase(),indexer=(url.searchParams.get("indexer")||"PreviewIndex")==="FullIndex"?"FullIndex":"PreviewIndex";
  if(!validTicker(ticker))return json({error:"Enter a valid ticker."},400);
  const period=indexer==="FullIndex"?"10y":"5y";
  const row=await first(env,"SELECT result,indexed_at FROM market_index WHERE ticker=? AND period=? AND horizon=30 AND indexer=?",ticker,period,indexer);
  if(!row)return json({analysis:null,indexer,available:false},404);
  return json({analysis:parse(row.result),indexer,indexed_at:row.indexed_at,available:true});
}
async function marketFeed(url,env){
  const q=(url.searchParams.get("q")||"").trim().slice(0,60);
  if(q){
    const searchUrl=new URL("https://query1.finance.yahoo.com/v1/finance/search");searchUrl.searchParams.set("q",q);searchUrl.searchParams.set("quotesCount","10");searchUrl.searchParams.set("newsCount","0");
    try{const r=await fetch(searchUrl,{headers:{"User-Agent":"Mozilla/5.0"},signal:AbortSignal.timeout(9000)});if(!r.ok)throw new Error("Search unavailable");const d=await r.json();return json({suggestions:(d.quotes||[]).filter(x=>x.symbol).map(x=>({symbol:x.symbol,name:x.longname||x.shortname||x.symbol,exchange:x.exchange||""}))});}catch{return json({suggestions:[]});}
  }
  const catalog=await all(env,"SELECT ticker,company,currency FROM ticker_catalog ORDER BY ticker LIMIT 60");
  const tickers=catalog.length?catalog.map(x=>x.ticker):POPULAR;
  const items=await Promise.all(tickers.slice(0,18).map(async ticker=>{
    try{
      const cachedQuote=await first(env,"SELECT * FROM market_quotes WHERE ticker=? AND updated_at>=?",ticker,new Date(Date.now()-5*60000).toISOString());
      const quote=cachedQuote?{ticker,company:cachedQuote.company,currency:cachedQuote.currency,price:cachedQuote.price,change_percent:cachedQuote.change_percent,as_of:cachedQuote.as_of,history:[],source:cachedQuote.source}:await yahooChart(ticker,"1y");
      if(!cachedQuote)await run(env,"INSERT INTO market_quotes(ticker,company,currency,price,change_percent,as_of,source,updated_at) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(ticker) DO UPDATE SET company=excluded.company,currency=excluded.currency,price=excluded.price,change_percent=excluded.change_percent,as_of=excluded.as_of,source=excluded.source,updated_at=excluded.updated_at",ticker,quote.company,quote.currency,quote.price,quote.change_percent,quote.as_of,quote.source,isoNow());
      const full=await first(env,"SELECT result,indexed_at FROM market_index WHERE ticker=? AND period='10y' AND horizon=30 AND indexer='FullIndex'",ticker);
      const preview=full?null:await first(env,"SELECT result,indexed_at FROM market_index WHERE ticker=? AND period='5y' AND horizon=30 AND indexer='PreviewIndex'",ticker);
      const row=full||preview,indexer=full?"FullIndex":preview?"PreviewIndex":null,result=parse(row?.result);
      await run(env,"INSERT INTO ticker_catalog(ticker,company,currency,last_indexed_at) VALUES(?,?,?,?) ON CONFLICT(ticker) DO UPDATE SET company=excluded.company,currency=excluded.currency",ticker,quote.company,quote.currency,row?.indexed_at||null);
      const hist=result?.history?.close||quote.history.slice(-60).map(x=>x.close);
      return {ticker,company:quote.company,currency:quote.currency,price:quote.price,change_percent:quote.change_percent,indexer,indexed_at:row?.indexed_at||null,history_preview:hist.slice(-45),forecast_preview:result?.forecast?.hybrid?.slice(0,30)||[],expected_change_percent:result?.forecast?.expected_change_percent??null,source:"Yahoo Finance"+(row?" + shared index":"")};
    }catch{
      return {ticker,company:catalog.find(x=>x.ticker===ticker)?.company||ticker,currency:"USD",price:null,change_percent:null,indexer:null,history_preview:[],forecast_preview:[],expected_change_percent:null,source:"Market data unavailable"};
    }
  }));
  const counts={PreviewIndex:0,FullIndex:0};
  for(const x of items)if(x.indexer)counts[x.indexer]++;
  return json({items,generated_at:isoNow(),index_counts:counts});
}
async function watchlist(req,env){
  const user=await authUser(req,env);if(!user)return json({error:"Sign in to use your watchlist."},401);
  const body=await req.json().catch(()=>({})),action=String(body.action||"list");
  if(action==="add"){
    const ticker=String(body.ticker||"").trim().toUpperCase();if(!validTicker(ticker))return json({error:"Enter a valid ticker."},400);
    const count=await first(env,"SELECT COUNT(*) AS n FROM watchlist_items WHERE user_id=?",user.id);
    const exists=await first(env,"SELECT id FROM watchlist_items WHERE user_id=? AND ticker=?",user.id,ticker);
    if(!exists&&Number(count?.n||0)>=100)return json({error:"Watchlist limit is 100 instruments."},409);
    await run(env,"INSERT OR IGNORE INTO watchlist_items(id,user_id,ticker,created_at) VALUES(?,?,?,?)",crypto.randomUUID(),user.id,ticker,isoNow());
  }else if(action==="remove"){
    const ticker=String(body.ticker||"").trim().toUpperCase();await run(env,"DELETE FROM watchlist_items WHERE user_id=? AND ticker=?",user.id,ticker);
  }else if(action!=="list")return json({error:"Unknown watchlist action."},400);
  const items=await all(env,"SELECT ticker,created_at FROM watchlist_items WHERE user_id=? ORDER BY created_at DESC",user.id);
  const output=await Promise.all(items.map(async item=>{
    let row=await first(env,"SELECT result,indexed_at,indexer FROM market_index WHERE ticker=? AND period='10y' AND horizon=30 AND indexer='FullIndex'",item.ticker);
    if(!row)row=await first(env,"SELECT result,indexed_at,indexer FROM market_index WHERE ticker=? AND period='5y' AND horizon=30 AND indexer='PreviewIndex'",item.ticker);
    const analysis=parse(row?.result);
    return {...item,indexer:row?.indexer||null,indexed_at:row?.indexed_at||null,analysis:analysis?{company:analysis.company,currency:analysis.currency,price:analysis.price,change_percent:analysis.change_percent,history_preview:analysis.history?.close?.slice(-60)||[],forecast_preview:analysis.forecast?.hybrid||[],expected_change_percent:analysis.forecast?.expected_change_percent}:null};
  }));
  return json({items:output});
}
async function requestMarketScan(env){
  const tickers=POPULAR.slice(0,12),started=[],cached=[];
  for(const ticker of tickers){
    const fresh=await first(env,"SELECT indexed_at FROM market_index WHERE ticker=? AND period='5y' AND horizon=30 AND indexer='PreviewIndex' AND indexed_at>=?",ticker,new Date(Date.now()-8*3600000).toISOString());
    if(fresh){cached.push(ticker);continue;}
    const active=await first(env,"SELECT id FROM analysis_jobs WHERE ticker=? AND save_to_indexer='PreviewIndex' AND status IN ('queued','running') LIMIT 1",ticker);
    if(active){started.push({ticker,id:active.id,reused:true});continue;}
    const id=crypto.randomUUID(),created=isoNow();
    await run(env,"INSERT INTO analysis_jobs(id,ticker,period,horizon,job_type,save_to_indexer,status,created_at,updated_at,progress,stage) VALUES(?,?,'5y',30,'scan','PreviewIndex','queued',?,?,0,'Market scan queued')",id,ticker,created,created);
    await env.ANALYSIS_QUEUE.send({jobId:id});
    started.push({ticker,id,reused:false});
  }
  return json({queued:started.length,cached:cached.length,jobs:started,cached_tickers:cached,message:"Market scan submitted to shared workers."},202);
}
async function listJobs(req,env){
  const user=await authUser(req,env);
  if(user)return json({jobs:await all(env,"SELECT id,ticker,save_to_indexer AS indexer,status,progress,stage,updated_at FROM analysis_jobs WHERE user_id=? OR job_type='scan' ORDER BY created_at DESC LIMIT 40",user.id)});
  return json({jobs:await all(env,"SELECT id,ticker,save_to_indexer AS indexer,status,progress,stage,updated_at FROM analysis_jobs WHERE job_type='scan' ORDER BY created_at DESC LIMIT 24")});
}
async function processJob(id,env){
  const job=await first(env,"SELECT * FROM analysis_jobs WHERE id=?",id);
  if(!job||job.status==="completed")return;
  try{
    await run(env,"UPDATE analysis_jobs SET status='running',attempts=attempts+1,progress=3,stage='Starting analysis worker',updated_at=? WHERE id=?",isoNow(),id);
    const result=await makeAnalysis(env,job);
    const indexer=job.save_to_indexer==="FullIndex"?"FullIndex":"PreviewIndex",period=indexer==="FullIndex"?"10y":"5y";
    const stored=JSON.stringify(result);
    await run(env,"INSERT INTO market_index(ticker,period,horizon,indexer,indexed_at,source_job_id,result) VALUES(?,?,?,?,?,?,?) ON CONFLICT(ticker,period,horizon,indexer) DO UPDATE SET indexed_at=excluded.indexed_at,source_job_id=excluded.source_job_id,result=excluded.result",job.ticker,period,job.horizon,indexer,isoNow(),id,stored);
    await run(env,"INSERT INTO ticker_catalog(ticker,company,currency,last_indexed_at,created_at) VALUES(?,?,?,?,?) ON CONFLICT(ticker) DO UPDATE SET company=excluded.company,currency=excluded.currency,last_indexed_at=excluded.last_indexed_at",job.ticker,result.company,result.currency,isoNow(),isoNow());
    await run(env,"UPDATE analysis_jobs SET status='completed',result=?,error=NULL,progress=100,stage='Analysis complete',updated_at=? WHERE id=?",stored,isoNow(),id);
  }catch(error){
    const message=String(error?.message||error||"Analysis failed").slice(0,800);
    await run(env,"UPDATE analysis_jobs SET status='failed',error=?,progress=0,stage='Analysis failed',updated_at=? WHERE id=?",message,isoNow(),id);
    throw error;
  }
}
async function refreshIndexes(env,indexer){
  const tickers=(await all(env,"SELECT ticker FROM ticker_catalog ORDER BY COALESCE(last_indexed_at,'') ASC LIMIT 24")).map(x=>x.ticker);
  const batch=[];
  for(const ticker of (tickers.length?tickers:POPULAR.slice(0,12))){
    const period=indexer==="FullIndex"?"10y":"5y";
    const active=await first(env,"SELECT id FROM analysis_jobs WHERE ticker=? AND save_to_indexer=? AND status IN ('queued','running') LIMIT 1",ticker,indexer);
    if(active)continue;
    const id=crypto.randomUUID(),created=isoNow();
    await run(env,"INSERT INTO analysis_jobs(id,ticker,period,horizon,save_to_indexer,status,created_at,updated_at,stage,progress) VALUES(?,?,?,30,?,'queued',?,?,?,0)",id,ticker,period,indexer,created,created,"Scheduled "+indexer+" refresh");
    batch.push({body:{jobId:id}});
  }
  for(let i=0;i<batch.length;i+=100)await env.ANALYSIS_QUEUE.sendBatch(batch.slice(i,i+100));
}
async function handleApi(req,env,url){
  const path=url.pathname;
  if(req.method==="OPTIONS")return new Response(null,{status:204,headers:CORS});
  if(path==="/api/health")return json({ok:true,service:"revised-finanx",database:"D1",queue:"Cloudflare Queues",time:isoNow()});
  if(path.startsWith("/api/auth/"))return authRoute(req,env,url);
  if(path==="/api/market-feed"&&req.method==="GET")return marketFeed(url,env);
  if(path==="/api/watchlist"&&req.method==="POST")return watchlist(req,env);
  if(path==="/api/market-scan"&&req.method==="POST")return requestMarketScan(env);
  if(path==="/api/jobs"&&req.method==="GET")return listJobs(req,env);
  if(path==="/api/request-analysis"&&req.method==="POST")return requestAnalysis(req,env);
  if(path==="/api/analysis-status"&&req.method==="GET")return analysisStatus(url,env);
  if(path==="/api/index-availability"&&req.method==="GET")return indexAvailability(url,env);
  if(path==="/api/stock-market-data"&&req.method==="GET")return stockMarketData(url,env);
  return json({error:"Not found."},404);
}
export default {
  async fetch(req,env,ctx){
    const url=new URL(req.url);
    if(url.pathname.startsWith("/api/")){
      try{return await handleApi(req,env,url);}catch(error){console.error("Finanx API error",error);return json({error:"The request could not be completed. Please try again."},500);}
    }
    if(url.pathname==="/favicon.ico")return new Response("",{status:204});
    return new Response(PAGE,{headers:{"Content-Type":"text/html; charset=utf-8","Cache-Control":"no-store","X-Content-Type-Options":"nosniff","Referrer-Policy":"strict-origin-when-cross-origin","X-Frame-Options":"DENY","Permissions-Policy":"camera=(), microphone=(), geolocation=()"}});
  },
  async queue(batch,env){
    for(const message of batch.messages){
      try{const id=message.body?.jobId;if(!id)throw new Error("Queue message has no jobId");await processJob(id,env);message.ack();}
      catch(error){console.error("Queue job failed",error);message.retry({delaySeconds:Math.min(300,20*Math.max(1,message.attempts||1))});}
    }
  },
  async scheduled(controller,env,ctx){
    const cron=controller.cron||"";
    if(cron==="0 2 * * *")ctx.waitUntil(refreshIndexes(env,"FullIndex"));
    else ctx.waitUntil(refreshIndexes(env,"PreviewIndex"));
    ctx.waitUntil(run(env,"DELETE FROM sessions WHERE expires_at<?",isoNow()));
    ctx.waitUntil(run(env,"DELETE FROM analysis_jobs WHERE status IN ('completed','failed') AND updated_at<?",new Date(Date.now()-14*86400000).toISOString()));
    ctx.waitUntil(run(env,"DELETE FROM api_rate_limits WHERE window_start<?",Date.now()-24*3600000));
  }
};
