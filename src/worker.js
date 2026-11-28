import PAGE from "./page.js";
import { getOriginalPredictions, ensemblePredictions, buildModelEvaluation, modelCandidates } from "./models.js";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,PATCH,DELETE,OPTIONS",
  "Access-Control-Allow-Headers": "Authorization,Content-Type",
  "Content-Type": "application/json; charset=utf-8"
};
const POPULAR = ["AAPL","MSFT","NVDA","GOOGL","AMZN","META","TSLA","BRK-B","JPM","LLY","AVGO","COST","AMD","NFLX","ORCL","CRM","ADBE","QCOM","INTC","WMT","HD","PG","KO","PEP","BAC","XOM","CVX","UNH","V","MA","DIS","UBER","PLTR","SHOP","SNOW","SPY","QQQ","DIA","IWM"];
const PREVIEW_VERSION = "finanx-preview-1";
const FULL_VERSION = "finanx-full-1";
const INDEX_CACHE_HOURS = 8;
const localRateLimits = new Map();
const localMarketQuotes = new Map();
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
  const bits=await crypto.subtle.deriveBits({name:"PBKDF2",salt:new Uint8Array(salt.match(/.{2}/g).map(x=>parseInt(x,16))),iterations:100000,hash:"SHA-256"},key,256);
  return hex(bits);
}
function tokenFrom(req){return (req.headers.get("Authorization")||"").replace(/^Bearer\s+/i,"").trim();}
function userShape(row){return {id:row.id,email:row.email,display_name:row.display_name||"",created_at:row.created_at,last_sign_in_at:row.last_sign_in_at};}
async function createSession(env,userId){
  const token=random(32),now=isoNow(),expires=new Date(Date.now()+30*86400000).toISOString();
  await run(env,"INSERT INTO sessions(token_hash,user_id,created_at,expires_at) VALUES(?,?,?,?)",await sha(token),userId,now,expires);
  return {access_token:token,token_type:"bearer",expires_at:Math.floor(Date.now()/1000)+2592000};
}
async function createKvSession(env,user){
  if(!env.AUTH_KV)throw new Error("Authentication fallback storage is not configured.");
  const token=random(32),expires=new Date(Date.now()+30*86400000).toISOString();
  await env.AUTH_KV.put("session:"+await sha(token),JSON.stringify({email:user.email,expires_at:expires,session_version:Number(user.session_version||0)}),{expirationTtl:2592000});
  return {access_token:token,token_type:"bearer",expires_at:Math.floor(Date.now()/1000)+2592000};
}
async function authUser(req,env){
  const token=tokenFrom(req);if(!token)return null;
  const tokenHash=await sha(token);
  try{
    const databaseUser=await first(env,"SELECT u.id,u.email,u.display_name,u.created_at,u.last_sign_in_at,s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?",tokenHash,isoNow());
    if(databaseUser)return databaseUser;
  }catch(error){
    console.warn("Finanx D1 session lookup unavailable; checking fallback auth storage.",String(error?.message||error));
  }
  if(!env.AUTH_KV)return null;
  const session=await env.AUTH_KV.get("session:"+tokenHash,"json");
  if(!session||!session.expires_at||Date.parse(session.expires_at)<=Date.now())return null;
  const user=await env.AUTH_KV.get("user-email:"+session.email,"json");
  if(!user||Number(session.session_version||0)!==Number(user.session_version||0))return null;
  return {...user,expires_at:session.expires_at};
}
async function rateLimit(env,req,key,max,windowMs){
  // Per-isolate best-effort throttling avoids a D1 write on every API request.
  // D1 is a shared daily quota; persisting every rate-limit counter exhausted it.
  const ip=(req.headers.get("cf-connecting-ip")||"unknown").slice(0,80),bucket=key+":"+ip,now=Date.now();
  let entry=localRateLimits.get(bucket);
  if(!entry||entry.resetAt<=now)entry={count:0,resetAt:now+windowMs};
  entry.count++;
  localRateLimits.set(bucket,entry);
  if(localRateLimits.size>5000){
    for(const [storedKey,storedValue] of localRateLimits){
      if(storedValue.resetAt<=now)localRateLimits.delete(storedKey);
      if(localRateLimits.size<=4000)break;
    }
  }
  return entry.count<=max;
}
async function authRoute(req,env,url){
  const route=url.pathname.split("/").pop(),method=req.method;
  const body=method==="POST"||method==="PATCH"?await req.json().catch(()=>({})): {};
  if(["signup","login"].includes(route)&&!await rateLimit(env,req,"auth-"+route,route==="signup"?5:12,3600000))return json({error:"Too many attempts. Try again later."},429);
  if(route==="signup"&&method==="POST"){
    const email=String(body.email||"").trim().toLowerCase(),password=String(body.password||"");
    if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||password.length<8||password.length>256)return json({error:"Enter a valid email and a password of at least 8 characters."},400);
    if(env.AUTH_KV){
      const existing=await env.AUTH_KV.get("user-email:"+email,"json");
      if(existing)return json({error:"An account with that email already exists."},409);
    }
    // Fail closed if D1 cannot verify whether this address already belongs to an existing account.
    let existingD1;
    try{existingD1=await first(env,"SELECT id FROM users WHERE email=? COLLATE NOCASE",email);}
    catch(error){console.error("Finanx signup duplicate check unavailable",error);return json({error:"Account registration is temporarily unavailable (AUTH-05)."},503);}
    if(existingD1)return json({error:"An account with that email already exists."},409);
    let salt,hash,id,created;
    try{salt=hex(crypto.getRandomValues(new Uint8Array(16)));hash=await passwordHash(password,salt);id=crypto.randomUUID();created=isoNow();}
    catch(error){console.error("Finanx signup stage: password preparation",error);return json({error:"Signup failed at password preparation (AUTH-01)."},500);}
    const user={id,email,password_hash:hash,password_salt:salt,display_name:"",created_at:created,last_sign_in_at:created,auth_store:"d1",session_version:0};
    let session;
    try{
      await run(env,"INSERT INTO users(id,email,password_hash,password_salt,created_at,last_sign_in_at) VALUES(?,?,?,?,?,?)",id,email,hash,salt,created,created);
      try{session=await createSession(env,id);}
      catch(error){
        if(!env.AUTH_KV)throw error;
        console.warn("Finanx signup: D1 session insert unavailable; using EU KV session storage.",String(error?.message||error));
        user.auth_store="kv";
        await env.AUTH_KV.put("user-email:"+email,JSON.stringify(user));
        session=await createKvSession(env,user);
      }
    }catch(error){
      const message=String(error?.message||error);
      if(/unique constraint|constraint failed.*users\.email|users\.email.*unique/i.test(message))return json({error:"An account with that email already exists."},409);
      if(!env.AUTH_KV){console.error("Finanx signup stage: user insert",error);return json({error:"Signup failed at account creation (AUTH-02)."},500);}
      console.warn("Finanx signup: D1 write unavailable; saving the account in EU KV.",message);
      user.auth_store="kv";
      try{
        await env.AUTH_KV.put("user-email:"+email,JSON.stringify(user));
        session=await createKvSession(env,user);
      }catch(kvError){
        console.error("Finanx signup fallback storage failed",kvError);
        return json({error:"Signup storage is temporarily unavailable (AUTH-04)."},503);
      }
    }
    return json({user:userShape(user),session:{...session,user:userShape(user)}},201);
  }
  if(route==="login"&&method==="POST"){
    const email=String(body.email||"").trim().toLowerCase(),password=String(body.password||"");
    if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||password.length<8||password.length>256)return json({error:"Email or password is incorrect."},401);
    let row=null,source="d1";
    try{row=await first(env,"SELECT * FROM users WHERE email=? COLLATE NOCASE",email);}
    catch(error){console.warn("Finanx D1 credential lookup unavailable; checking EU KV.",String(error?.message||error));}
    if(!row&&env.AUTH_KV){
      row=await env.AUTH_KV.get("user-email:"+email,"json");
      if(row)source="kv";
    }
    if(!row||await passwordHash(password,row.password_salt)!==row.password_hash)return json({error:"Email or password is incorrect."},401);
    const signed=isoNow();row.last_sign_in_at=signed;
    if(source==="kv"||row.auth_store==="kv"){
      row.auth_store="kv";
      await env.AUTH_KV.put("user-email:"+email,JSON.stringify(row));
      const session=await createKvSession(env,row),user=userShape(row);
      return json({user,session:{...session,user}});
    }
    try{
      await run(env,"UPDATE users SET last_sign_in_at=? WHERE id=?",signed,row.id);
      const session=await createSession(env,row.id),user=userShape(row);
      return json({user,session:{...session,user}});
    }catch(error){
      if(!env.AUTH_KV)throw error;
      console.warn("Finanx login: D1 session unavailable; using EU KV session storage.",String(error?.message||error));
      row.auth_store="kv";
      await env.AUTH_KV.put("user-email:"+email,JSON.stringify(row));
      const session=await createKvSession(env,row),user=userShape(row);
      return json({user,session:{...session,user}});
    }
  }
  if(route==="me"&&method==="GET"){
    const user=await authUser(req,env);if(!user)return json({error:"Your session has expired. Sign in again."},401);
    return json({user:userShape(user)});
  }
  if(route==="logout"&&method==="POST"){
    const token=tokenFrom(req);
    if(token){
      const tokenHash=await sha(token);
      try{await run(env,"DELETE FROM sessions WHERE token_hash=?",tokenHash);}catch(error){console.warn("Finanx D1 logout cleanup unavailable.",String(error?.message||error));}
      if(env.AUTH_KV)await env.AUTH_KV.delete("session:"+tokenHash);
    }
    return json({success:true});
  }
  if(route==="password"&&method==="PATCH"){
    const user=await authUser(req,env);if(!user)return json({error:"Sign in again."},401);
    const password=String(body.password||"");if(password.length<8||password.length>256)return json({error:"Password must contain at least 8 characters."},400);
    const salt=hex(crypto.getRandomValues(new Uint8Array(16))),hash=await passwordHash(password,salt);
    if(user.auth_store==="kv"){
      const stored=await env.AUTH_KV.get("user-email:"+user.email,"json");
      if(!stored)return json({error:"Account record not found."},404);
      stored.password_hash=hash;stored.password_salt=salt;stored.session_version=Number(stored.session_version||0)+1;
      await env.AUTH_KV.put("user-email:"+user.email,JSON.stringify(stored));
      const tokenHash=await sha(tokenFrom(req)),session=await env.AUTH_KV.get("session:"+tokenHash,"json");
      if(session){
        session.session_version=stored.session_version;
        const ttl=Math.max(60,Math.ceil((Date.parse(session.expires_at)-Date.now())/1000));
        await env.AUTH_KV.put("session:"+tokenHash,JSON.stringify(session),{expirationTtl:ttl});
      }
      return json({success:true,sessions_revoked:true});
    }
    await env.DB.batch([
      stmt(env,"UPDATE users SET password_hash=?,password_salt=? WHERE id=?",hash,salt,user.id),
      stmt(env,"DELETE FROM sessions WHERE user_id=? AND token_hash<>?",user.id,await sha(tokenFrom(req)))
    ]);
    return json({success:true,sessions_revoked:true});
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
async function loadLegacyGlobalWeights(env,indexer){
  const prefix=indexer+":";
  const rows=await all(env,"SELECT model_key,observations,correct,accuracy,weight,updated_at FROM model_learning_state WHERE model_key LIKE ?",prefix+"%");
  return Object.fromEntries(rows.map(row=>[row.model_key.slice(prefix.length),row]));
}
async function loadGlobalWeights(env,indexer){
  if(env.AUTH_KV){
    try{
      const saved=await env.AUTH_KV.get("model-learning:"+indexer,"json");
      if(saved?.weights&&typeof saved.weights==="object")return saved.weights;
    }catch(error){console.warn("Finanx model profile KV read unavailable; using legacy D1 profiles.",String(error?.message||error));}
  }
  return loadLegacyGlobalWeights(env,indexer);
}
async function updateGlobalLearning(env,scoreMap,indexer){
  if(!env.AUTH_KV)return;
  const key="model-learning:"+indexer;
  try{
    const saved=await env.AUTH_KV.get(key,"json");
    // Rebuild model profiles once per day instead of writing 21–29 rows per index.
    const lastUpdated=Date.parse(saved?.updated_at||"");
    if(Number.isFinite(lastUpdated)&&Date.now()-lastUpdated<24*3600000)return;
    const weights={...(saved?.weights&&typeof saved.weights==="object"?saved.weights:await loadLegacyGlobalWeights(env,indexer))};
    const updated=isoNow();
    for(const [modelKey,score] of Object.entries(scoreMap)){
      if(!score||Number(score.observations||0)<=0)continue;
      const previous=weights[modelKey]||{};
      const observations=Number(previous.observations||0)+Number(score.observations||0);
      const correct=Number(previous.correct||0)+Number(score.correct||0);
      const accuracy=observations?correct/observations:0.5;
      weights[modelKey]={model_key:indexer+":"+modelKey,observations,correct,accuracy,weight:clamp(1+(accuracy-0.5)*2,0.25,2.5),updated_at:updated};
    }
    await env.AUTH_KV.put(key,JSON.stringify({updated_at:updated,weights}),{expirationTtl:90*86400});
  }catch(error){console.warn("Finanx model profile update skipped.",String(error?.message||error));}
}
async function updateJobProgress(env,id,progress,stage){
  if(!env.AUTH_KV)return;
  try{await env.AUTH_KV.put("analysis-progress:"+id,JSON.stringify({progress,stage,updated_at:isoNow()}),{expirationTtl:7*86400});}
  catch(error){console.warn("Finanx progress snapshot skipped.",String(error?.message||error));}
}
async function makeAnalysis(env,job){
  const indexer=job.save_to_indexer==="FullIndex"?"FullIndex":"PreviewIndex";
  const period=indexer==="FullIndex"?"10y":(job.period||"5y");
  await updateJobProgress(env,job.id,5,"Downloading and validating market history");
  const quote=await yahooChart(job.ticker,period);
  const fundamentals=await yahooFundamentals(job.ticker),newsContext=await getTickerNews(job.ticker);
  const rows=quote.history,closes=rows.map(x=>x.close),volumes=rows.map(x=>x.volume||0),horizon=clamp(Number(job.horizon||30),1,504);
  await updateJobProgress(env,job.id,27,"Evaluating chronological holdouts");
  const previousWeights=await loadGlobalWeights(env,indexer);
  const full=indexer==="FullIndex";
  const evaluation=buildModelEvaluation(closes,volumes,previousWeights,full);
  await updateGlobalLearning(env,evaluation.stats,indexer);
  await updateJobProgress(env,job.id,57,"Updating global model profiles");
  const globalWeights=await loadGlobalWeights(env,indexer);
  const original=getOriginalPredictions(closes,volumes);
  const predictions=ensemblePredictions(original.predictions,globalWeights,full);
  const candidates=modelCandidates(predictions,evaluation.stats,globalWeights);
  const dailyVol=Number(original.diagnostics.volatility||0.015);
  const rawModelSignal=clamp(Number(predictions.primary||0),-0.02,0.02),newsAdjustment=clamp(Number(newsContext.temporal.signal||0)*dailyVol*.025,-.0008,.0008),dailySignal=clamp(rawModelSignal+newsAdjustment,-0.02,0.02);
  let cumulative=0;
  const forecast=[],lower=[],upper=[];
  for(let i=1;i<=horizon;i++){
    cumulative+=dailySignal*Math.pow(0.965,i-1);
    const center=closes.at(-1)*Math.exp(cumulative),uncertainty=1.65*dailyVol*Math.sqrt(i);
    forecast.push(Number(center.toFixed(4)));
    lower.push(Number((closes.at(-1)*Math.exp(cumulative-uncertainty)).toFixed(4)));
    upper.push(Number((closes.at(-1)*Math.exp(cumulative+uncertainty)).toFixed(4)));
  }
  const expected=forecast.length?100*(forecast.at(-1)/closes.at(-1)-1):0;
  const accuracy=Number(evaluation.stats.primary?.accuracy??0.5);
  const risk=clamp(30+dailyVol*1200+Math.max(0,-Number(original.diagnostics.drawdown||0))*85,0,100);
  const modelVersion=full?"finanx-full-ensemble-v2":"finanx-preview-ensemble-v2";
  const result={
    ticker:job.ticker,company:quote.company,currency:quote.currency,exchange:quote.exchange,price:quote.price,change_percent:quote.change_percent,as_of:quote.as_of,data_source:quote.source,indexed_at:isoNow(),
    history:{period,dates:rows.slice(-2600).map(x=>x.date),close:rows.slice(-2600).map(x=>x.close),volume:rows.slice(-2600).map(x=>x.volume)},
    forecast:{horizon,hybrid:forecast,lower_bound:lower,upper_bound:upper,expected_change_percent:Number(expected.toFixed(2)),model_name:"Adaptive Primary Hybrid"},
    risk:{score:Number(risk.toFixed(1)),annualized_volatility:Number((dailyVol*Math.sqrt(252)*100).toFixed(2)),recent_drawdown:Number((Number(original.diagnostics.drawdown||0)*100).toFixed(2)),rsi:Number(original.diagnostics.rsi||50).toFixed(1)},
    model:{version:modelVersion,primary:"Adaptive Primary Hybrid",original_count:full?15:7,hybrid_count:10,meta_count:3,metrics:{backtest:{directional_accuracy:Number(accuracy.toFixed(4)),validation_windows:evaluation.windows,validation_horizon:"1 trading day"}},learning_observations:candidates.reduce((sum,c)=>sum+c.observations,0),candidates},
    fundamentals:{...fundamentals,source:"Yahoo Finance quote summary"},news_context:{...newsContext.temporal,items:newsContext.items,signal_adjustment:Number(newsAdjustment.toFixed(6)),method:"Simple headline keyword signal blended at a low weight; time buckets are independently weighted and this is not a trained sentiment model."}
  };
  await updateJobProgress(env,job.id,86,"Writing shared index and forecast");
  return result;
}
async function enqueueJob(env,job){
  await env.ANALYSIS_QUEUE.send({jobId:job.id});
}
async function requestAnalysis(req,env){
  const body=await req.json().catch(()=>({})),ticker=String(body.ticker||"").trim().toUpperCase(),indexer=String(body.save_to_indexer||body.indexer||"PreviewIndex").toLowerCase()==="fullindex"?"FullIndex":"PreviewIndex";
  if(!validTicker(ticker))return json({error:"Enter a valid stock ticker."},400);
  const period=indexer==="FullIndex"?"10y":"5y",horizon=Number(body.horizon??(indexer==="FullIndex"?60:30)),maxAge=INDEX_CACHE_HOURS,hardRescan=body.hard_rescan===true;
  if(!Number.isInteger(horizon)||horizon<1||horizon>504)return json({error:"Horizon must be a whole number from 1 to 504 trading days."},400);
  if(!await rateLimit(env,req,"analysis-request",90,3600000))return json({error:"Analysis request limit reached for this connection. Try later."},429);
  const cutoff=new Date(Date.now()-maxAge*3600000).toISOString();
  if(!hardRescan){
    const cached=await first(env,"SELECT result,indexed_at,source_job_id FROM market_index WHERE ticker=? AND period=? AND horizon=? AND indexer=? AND indexed_at>=? LIMIT 1",ticker,period,horizon,indexer,cutoff);
    if(cached?.result)return json({status:"completed",ticker,indexer,cached:true,result:parse(cached.result),id:cached.source_job_id,progress:100,stage:"Loaded shared index"});
  }
  const active=await first(env,"SELECT id,status,progress,stage FROM analysis_jobs WHERE ticker=? AND period=? AND horizon=? AND save_to_indexer=? AND status IN ('queued','running') ORDER BY created_at DESC LIMIT 1",ticker,period,horizon,indexer);
  if(active)return json({...active,ticker,indexer,reused:true},202);
  const user=await authUser(req,env),id=crypto.randomUUID(),created=isoNow();
  await run(env,"INSERT INTO analysis_jobs(id,ticker,period,horizon,job_type,scan_source,save_to_indexer,status,created_at,updated_at,progress,stage,user_id) VALUES(?,?,?,?,?,'both',?,'queued',?,?,0,'Waiting for analysis worker',?)",id,ticker,period,horizon,hardRescan?"hard_rescan":"analysis",indexer,created,created,user?.id||null);
  try{await enqueueJob(env,{id});}
  catch(error){await run(env,"UPDATE analysis_jobs SET status='failed',error=?,updated_at=?,stage='Could not reach the analysis queue' WHERE id=?",String(error.message||error),isoNow(),id);return json({error:"The analysis queue is temporarily unavailable."},503);}
  return json({id,status:"queued",ticker,indexer,period,horizon,progress:0,stage:"Waiting for analysis worker"},202);
}
async function analysisStatus(req,url,env){
  const id=url.searchParams.get("id")||"";
  if(!/^[0-9a-f-]{36}$/i.test(id))return json({error:"Invalid job identifier."},400);
  const job=await first(env,"SELECT id,ticker,status,result,error,created_at,updated_at,progress,stage,attempts,period,horizon,save_to_indexer,user_id FROM analysis_jobs WHERE id=?",id);
  if(!job)return json({error:"Analysis job not found."},404);
  if(job.user_id){
    const user=await authUser(req,env);
    if(!user||user.id!==job.user_id)return json({error:"Analysis job not found."},404);
  }
  const {user_id,...visible}=job;
  const progressSnapshot=env.AUTH_KV?await env.AUTH_KV.get("analysis-progress:"+id,"json").catch(()=>null):null;
  const useSnapshot=progressSnapshot&&["queued","running"].includes(job.status);
  return json({...visible,...(useSnapshot?progressSnapshot:{}),result:parse(job.result),progress:job.status==="completed"?100:Number(useSnapshot?progressSnapshot.progress:job.progress||0)});
}
async function indexAvailability(url,env){
  const ticker=(url.searchParams.get("ticker")||"").toUpperCase(),requestedHorizon=url.searchParams.get("horizon");
  if(requestedHorizon!==null&&(!Number.isInteger(Number(requestedHorizon))||Number(requestedHorizon)<1||Number(requestedHorizon)>504))return json({error:"Horizon must be a whole number from 1 to 504 trading days."},400);
  if(!validTicker(ticker))return json({error:"Enter a valid ticker."},400);
  const definitions=[{id:"PreviewIndex",period:"5y",horizon:30,age:INDEX_CACHE_HOURS},{id:"FullIndex",period:"10y",horizon:60,age:INDEX_CACHE_HOURS}],indexes=[];
  for(const item of definitions){
    const cutoff=new Date(Date.now()-item.age*3600000).toISOString();
    const row=await first(env,"SELECT indexed_at FROM market_index WHERE ticker=? AND period=? AND horizon=? AND indexer=? AND indexed_at>=?",ticker,item.period,item.horizon,item.id,cutoff);
    if(row)indexes.push({id:item.id,label:item.id,indexed_at:row.indexed_at});
  }
  return json({ticker,indexes,available:indexes.map(x=>x.id),checked_at:isoNow()});
}
async function stockMarketData(url,env){
  const ticker=(url.searchParams.get("ticker")||"").toUpperCase(),indexer=(url.searchParams.get("indexer")||"PreviewIndex")==="FullIndex"?"FullIndex":"PreviewIndex",horizon=Number(url.searchParams.get("horizon")||(indexer==="FullIndex"?60:30));
  if(!validTicker(ticker))return json({error:"Enter a valid ticker."},400);
  if(!Number.isInteger(horizon)||horizon<1||horizon>504)return json({error:"Horizon must be a whole number from 1 to 504 trading days."},400);
  const period=indexer==="FullIndex"?"10y":"5y";
  const row=await first(env,"SELECT result,indexed_at FROM market_index WHERE ticker=? AND period=? AND horizon=? AND indexer=?",ticker,period,horizon,indexer);
  if(!row)return json({analysis:null,indexer,available:false},404);
  return json({analysis:parse(row.result),indexer,indexed_at:row.indexed_at,available:true});
}
async function indexedStats(env){
  const preview=await first(env,"SELECT COUNT(DISTINCT ticker) AS tickers,COUNT(*) AS records,MAX(indexed_at) AS latest FROM market_index WHERE indexer='PreviewIndex'");
  const full=await first(env,"SELECT COUNT(DISTINCT ticker) AS tickers,COUNT(*) AS records,MAX(indexed_at) AS latest FROM market_index WHERE indexer='FullIndex'");
  const tracked=await first(env,"SELECT COUNT(DISTINCT ticker) AS tickers FROM ticker_catalog");
  return json({tracked:Number(tracked?.tickers||0),preview:{tickers:Number(preview?.tickers||0),records:Number(preview?.records||0),latest:preview?.latest||null},full:{tickers:Number(full?.tickers||0),records:Number(full?.records||0),latest:full?.latest||null},generated_at:isoNow()});
}
async function mapLimit(items,limit,mapper){
  const output=new Array(items.length);let cursor=0;
  await Promise.all(Array.from({length:Math.min(limit,items.length)},async()=>{
    while(true){const index=cursor++;if(index>=items.length)return;output[index]=await mapper(items[index],index);}
  }));
  return output;
}
async function fetchYahooNews(query,limit=12){
  const url=new URL("https://query1.finance.yahoo.com/v1/finance/search");
  url.searchParams.set("q",query);url.searchParams.set("quotesCount","0");url.searchParams.set("newsCount",String(limit));
  const response=await fetch(url,{headers:{"User-Agent":"Mozilla/5.0 FinanxResearch/1.0","Accept":"application/json"},signal:AbortSignal.timeout(10000)});
  if(!response.ok)throw new Error("News provider unavailable");
  const data=await response.json();
  const now=Date.now(),items=(data.news||[]).map(item=>{
    const ts=Number(item.providerPublishTime||item.pubDate||item.publishedAt||0);
    const published=ts>1e12?ts:ts*1000;
    const resolutions=item.thumbnail?.resolutions||[];const image=resolutions.slice().sort((a,b)=>Number(b.width||0)-Number(a.width||0))[0]?.url||item.thumbnail?.url||item.image?.url||item.image||item.images?.[0]?.url||"";return {title:String(item.title||""),summary:String(item.summary||item.description||""),publisher:String(item.publisher||item.provider||"News source"),url:String(item.link||item.url||""),image:String(image||""),published_at:published?new Date(published).toISOString():null,age_hours:published?Math.max(0,(now-published)/3600000):null};
  }).filter(item=>item.title&&item.url);
  return items;
}
function validNewsArticleURL(raw){try{const u=new URL(raw);if(!["http:","https:"].includes(u.protocol)||u.username||u.password||u.port&&u.port!=="80"&&u.port!=="443")return null;const h=u.hostname.toLowerCase();if(h==="localhost"||h.endsWith(".localhost")||h.endsWith(".local")||h.endsWith(".internal")||h==="0.0.0.0"||h==="127.0.0.1"||h==="::1"||/^\d{1,3}(?:\.\d{1,3}){3}$/.test(h)||h.startsWith("[")||h.includes("metadata.google"))return null;return u;}catch{return null;}}
function decodeNewsEntities(text){return text.replace(/&nbsp;/gi," ").replace(/&amp;/gi,"&").replace(/&quot;/gi,'"').replace(/&#39;/gi,"'").replace(/&lt;/gi,"<").replace(/&gt;/gi,">").replace(/&#(\d+);/g,(_,n)=>String.fromCodePoint(Number(n))).replace(/&#x([\da-f]+);/gi,(_,n)=>String.fromCodePoint(parseInt(n,16)));}
function newsArticleRoute(url,env,req){const raw=url.searchParams.get("url")||"",articleURL=validNewsArticleURL(raw);if(!articleURL)return json({error:"Invalid article URL."},400);return (async()=>{if(!await rateLimit(env,req,"news-article",10,60000))return json({error:"Article fetch limit reached. Try again shortly."},429);try{const response=await fetch(articleURL.href,{headers:{"User-Agent":"Mozilla/5.0 (compatible; FinanxNewsReader/1.0)","Accept":"text/html,application/xhtml+xml"},redirect:"manual",signal:AbortSignal.timeout(12000)});if(response.status>=300&&response.status<400)return json({error:"This publisher redirects the article request; use the original-source link."},502);if(!response.ok)return json({error:"Publisher returned HTTP "+response.status},502);const type=response.headers.get("content-type")||"";if(!type.includes("text/html"))return json({error:"Publisher did not return an HTML article."},415);const html=(await response.text()).slice(0,1200000);const meta=(key)=>{for(const match of html.matchAll(/<meta\b[^>]*>/gi)){const tag=match[0],attrs={};for(const a of tag.matchAll(/([a-zA-Z0-9_-]+)\s*=\s*("[^"]*"|'[^']*')/g)){const raw=a[2],value=raw.slice(1,-1);attrs[a[1].toLowerCase()]=decodeNewsEntities(value);}if((attrs.property||attrs.name||"").toLowerCase()===key.toLowerCase())return (attrs.content||"").trim();}return "";};const title=meta("og:title")||meta("twitter:title")||((html.match(/<title[^>]*>([\s\S]*?)<\/title>/i)||[])[1]||"").replace(/<[^>]+>/g," ").trim();const image=meta("og:image")||meta("twitter:image");const author=meta("author")||meta("article:author");const published=meta("article:published_time")||meta("datePublished");let body="",markup="";for(const block of html.matchAll(/<script[^>]+type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi)){try{const data=JSON.parse(block[1]);const collect=o=>{if(!o||typeof o!=="object")return;if(Array.isArray(o)){o.forEach(collect);return;}if(o.articleBody&&typeof o.articleBody==="string"){body=o.articleBody;markup=body.includes("<")?body:"";}collect(o["@graph"]);};collect(data);if(body)break;}catch{}}if(!body){let source=html.replace(/<(script|style|noscript|svg|iframe|nav|footer|aside|form|header|button)[^>]*>[\s\S]*?<\/\1>/gi," ").replace(/<!--[\s\S]*?-->/g," ");const article=(source.match(/<article[^>]*>([\s\S]*?)<\/article>/i)||[])[1],main=(source.match(/<main[^>]*>([\s\S]*?)<\/main>/i)||[])[1],candidate=article||main||source;const blocks=[...candidate.matchAll(/<(p|h[1-6]|li|blockquote|strong|em)[^>]*>[\s\S]*?<\/\1>/gi)].map(m=>m[0]).filter(x=>x.replace(/<[^>]+>/g," ").replace(/\s+/g," ").trim().length>45);markup=blocks.join("");body=markup.replace(/<[^>]+>/g," ").replace(/&nbsp;/gi," ").replace(/\s+/g," ").trim();}body=decodeNewsEntities(body.replace(/<[^>]+>/g," ").replace(/\s+/g," ").trim());if(body.length<250)return json({error:"Could not extract readable article text from this publisher. It may require scripts or access restrictions."},422);const excerpt=body.slice(0,400).trim();const host=articleURL.hostname.toLowerCase(),yahooAuthorized=host==="news.yahoo.com"||host==="yahoo.com"||host.endsWith(".yahoo.com");return json({url:articleURL.href,title,author,image,published_at:published,excerpt,html_body:yahooAuthorized?markup:null,full_text:yahooAuthorized?body:null,full_text_available:yahooAuthorized,source_host:articleURL.hostname});}catch(error){return json({error:"Unable to fetch this article. The publisher may block automated access."},502);}})();}async function fetchCapitalDataWire(query,limit=12){
  const url=new URL("https://capitaldatawire.com/api/v1/articles");
  url.searchParams.set("limit",String(limit));
  const asset=(query.match(/[A-Z]{1,5}(?:\.[A-Z])?/i)||[])[0];
  if(asset&&query.length<20)url.searchParams.set("asset",asset.toUpperCase());
  const response=await fetch(url.href,{headers:{"Accept":"application/json"},signal:AbortSignal.timeout(10000)});
  if(!response.ok)throw new Error("Capital Data Wire unavailable");
  const data=await response.json();
  return (Array.isArray(data.data)?data.data:[]).filter(item=>item&&item.title&&item.body).map(item=>({
    title:String(item.title),summary:String(item.summary||""),publisher:"Capital Data Wire",url:String(item.url||""),image:"",
    published_at:item.published_at||null,age_hours:item.published_at?Math.max(0,(Date.now()-new Date(item.published_at).getTime())/3600000):null,
    source_type:"capitaldatawire",article_id:String(item.id||""),full_text:String(item.body||""),
    author:String(item.author_name||"Capital Data Wire Newsdesk"),attribution:String(item.attribution||"Capital Data Wire")
  })).filter(item=>item.url&&item.full_text);
}
function newsRoute(url,env,req){
  const query=(url.searchParams.get("q")||"market news").trim().slice(0,80);
  return (async()=>{
    if(!await rateLimit(env,req,"news-feed",20,60000))return json({error:"News refresh limit reached. Try again shortly."},429);
    const [yahoo,wire]=await Promise.allSettled([fetchYahooNews(query,12),fetchCapitalDataWire(query,12)]);
    const items=[...(yahoo.status==="fulfilled"?yahoo.value:[]),...(wire.status==="fulfilled"?wire.value:[])];
    items.sort((a,b)=>new Date(b.published_at||0)-new Date(a.published_at||0));
    return json({items:items.slice(0,20),query,generated_at:isoNow(),capital_data_wire_available:wire.status==="fulfilled"});
  })();
}
function scoreHeadline(text){
  const positive=/beat(s|ing)?|upgrade(d|s)?|growth|surge(d|s)?|record|profit|strong|rise(s|n)?|gain(s|ed)?|bullish|buyback|outperform|positive|expansion|approval|launch|deal|contract|dividend|improv(e|ed|ement)/i;
  const negative=/miss(es|ed)?|downgrade(d|s)?|decline(d|s)?|drop(s|ped)?|fall(s|en)?|loss(es)?|weak|bearish|cut(s)?|warning|lawsuit|investigation|recall|layoff|risk|negative|crash|disappoint(s|ed)?|debt|fine|fraud/i;
  const p=(String(text).match(new RegExp(positive.source,"gi"))||[]).length,n=(String(text).match(new RegExp(negative.source,"gi"))||[]).length;
  return Math.max(-1,Math.min(1,(p-n)/Math.max(2,p+n)));
}
function summarizeNewsByTime(items){
  const ranges=[{key:"0-6h",label:"Last 6 hours",min:0,max:6,weight:1},{key:"6-24h",label:"6–24 hours",min:6,max:24,weight:.8},{key:"1-3d",label:"1–3 days",min:24,max:72,weight:.55},{key:"3-7d",label:"3–7 days",min:72,max:168,weight:.3}];
  const buckets=ranges.map(range=>{const news=items.filter(item=>item.age_hours!=null&&item.age_hours>=range.min&&item.age_hours<range.max);return {...range,count:news.length,signal:news.length?news.reduce((sum,item)=>sum+scoreHeadline(item.title+" "+item.summary),0)/news.length:0};});
  const populated=buckets.filter(bucket=>bucket.count);
  const weighted=populated.reduce((sum,bucket)=>sum+bucket.signal*bucket.weight* Math.min(1,bucket.count/3),0);
  const totalWeight=populated.reduce((sum,bucket)=>sum+bucket.weight*Math.min(1,bucket.count/3),0);
  return {buckets,signal:totalWeight?Math.max(-1,Math.min(1,weighted/totalWeight)):0,coverage:populated.length};
}
async function getTickerNews(ticker){
  try{const items=await fetchYahooNews(ticker,20);return {items,temporal:summarizeNewsByTime(items)};}
  catch{return {items:[],temporal:summarizeNewsByTime([]),unavailable:true};}
}

async function marketFeed(url,env,req){
  const q=(url.searchParams.get("q")||"").trim().slice(0,60);
  if(q){
    if(!await rateLimit(env,req,"market-search",45,60000))return json({error:"Search limit reached. Try again shortly."},429);
    const searchUrl=new URL("https://query1.finance.yahoo.com/v1/finance/search");
    searchUrl.searchParams.set("q",q);searchUrl.searchParams.set("quotesCount","10");searchUrl.searchParams.set("newsCount","0");
    try{
      const response=await fetch(searchUrl,{headers:{"User-Agent":"Mozilla/5.0"},signal:AbortSignal.timeout(9000)});
      if(!response.ok)throw new Error("Search unavailable");
      const data=await response.json();
      return json({suggestions:(data.quotes||[]).filter(x=>x.symbol).map(x=>({symbol:x.symbol,name:x.longname||x.shortname||x.symbol,exchange:x.exchange||""}))});
    }catch{return json({suggestions:[]});}
  }

  // A throttled refresh must not make the market disappear. Read the D1 snapshot
  // first and serve it even when this IP has reached the upstream-refresh limit.
  const refreshAllowed=await rateLimit(env,req,"market-feed",15,60000);
  const [catalog,indexedTickers]=await Promise.all([
    all(env,"SELECT ticker,company,currency FROM ticker_catalog ORDER BY COALESCE(last_indexed_at,'') DESC LIMIT 60"),
    all(env,"SELECT ticker,MAX(indexed_at) AS latest FROM market_index GROUP BY ticker ORDER BY latest DESC LIMIT 100")
  ]);
  const tickers=POPULAR.slice(0,8).concat(indexedTickers.map(x=>x.ticker),catalog.map(x=>x.ticker),POPULAR.slice(8))
    .filter((ticker,index,items)=>validTicker(ticker)&&items.indexOf(ticker)===index).slice(0,24);
  if(!tickers.length)return json({items:[],generated_at:isoNow(),index_counts:{PreviewIndex:0,FullIndex:0},stale:!refreshAllowed,refresh_limited:!refreshAllowed});

  const placeholders=tickers.map(()=>"?").join(",");
  const [quoteRows,indexRows]=await Promise.all([
    all(env,"SELECT * FROM market_quotes WHERE ticker IN ("+placeholders+")",...tickers),
    all(env,"SELECT ticker,period,indexer,indexed_at,result FROM market_index WHERE ticker IN ("+placeholders+") AND ((indexer='FullIndex' AND horizon=60 AND indexed_at>=?) OR (indexer='PreviewIndex' AND horizon=30 AND indexed_at>=?)) ORDER BY indexed_at DESC",...tickers,new Date(Date.now()-INDEX_CACHE_HOURS*3600000).toISOString(),new Date(Date.now()-INDEX_CACHE_HOURS*3600000).toISOString())
  ]);
  const quotesByTicker=new Map(quoteRows.map(row=>[row.ticker,row]));
  const catalogByTicker=new Map(catalog.map(row=>[row.ticker,row]));
  const indexesByTicker=new Map();
  for(const row of indexRows){
    const existing=indexesByTicker.get(row.ticker);
    if(!existing||(row.indexer==="PreviewIndex"&&existing.indexer!=="PreviewIndex")||
      (row.indexer===existing.indexer&&row.indexed_at>existing.indexed_at))indexesByTicker.set(row.ticker,row);
  }

  const cachedItems=tickers.map(ticker=>{
    const cached=quotesByTicker.get(ticker);
    return {ticker,quote:cached||{ticker,company:catalogByTicker.get(ticker)?.company||ticker,currency:catalogByTicker.get(ticker)?.currency||"USD",price:null,change_percent:null,as_of:null,source:"Quote temporarily unavailable"}};
  });
  const refreshed=refreshAllowed?await mapLimit(tickers,6,async ticker=>{
    const cached=quotesByTicker.get(ticker)||null;
    const memory=localMarketQuotes.get(ticker);
    if(memory&&Date.now()-memory.cachedAt<90000)return {ticker,quote:memory.quote};
    try{
      const quote=await yahooChart(ticker,"1y");
      localMarketQuotes.set(ticker,{quote,cachedAt:Date.now()});
      if(localMarketQuotes.size>160){for(const [key,value] of localMarketQuotes){if(Date.now()-value.cachedAt>10*60000)localMarketQuotes.delete(key);}}
      return {ticker,quote};
    }catch{
      return {ticker,quote:cached||{ticker,company:catalogByTicker.get(ticker)?.company||ticker,currency:catalogByTicker.get(ticker)?.currency||"USD",price:null,change_percent:null,as_of:null,source:"Quote temporarily unavailable"}};
    }
  }):cachedItems;
  // Volatile live quotes are not stored in D1; only completed shared indexes are persisted.
  const now=isoNow();

  const items=refreshed.map(({ticker,quote})=>{
    const indexed=indexesByTicker.get(ticker),analysis=parse(indexed?.result);
    const history=analysis?.history?.close||(quote.history||[]).slice(-60).map(row=>row.close);
    return {
      ticker,company:quote.company||ticker,currency:quote.currency||"USD",
      price:quote.price??null,change_percent:quote.change_percent??null,as_of:quote.as_of||null,
      indexer:indexed?.indexer||null,indexed_at:indexed?.indexed_at||null,
      history_preview:history.slice(-45),
      forecast_preview:analysis?.forecast?.hybrid?.slice(0,indexed?.horizon||30)||[],forecast_horizon:indexed?.horizon||30,
      expected_change_percent:analysis?.forecast?.expected_change_percent??null,
      source:(quote.source||"Yahoo Finance")+(indexed?" + shared index":"")
    };
  });
  const counts={PreviewIndex:0,FullIndex:0};
  for(const item of items)if(item.indexer)counts[item.indexer]++;
  return json({items,generated_at:now,index_counts:counts,stale:!refreshAllowed,refresh_limited:!refreshAllowed,message:refreshAllowed?"Market snapshot refreshed.":"Refresh limit reached; serving the saved D1 snapshot."});
}
async function cachedMarketFeed(url,env,req){
  if(url.searchParams.has("q"))return marketFeed(url,env,req);
  const cache=globalThis.caches?.default;
  if(!cache)return marketFeed(url,env,req);
  const key=new Request(new URL("/__finanx_cache/market-feed",url.origin).href);
  try{const hit=await cache.match(key);if(hit)return hit;}
  catch(error){console.warn("Finanx market-feed cache read skipped.",String(error?.message||error));}
  const response=await marketFeed(url,env,req);
  if(response.status===200){
    try{const clone=response.clone(),headers=new Headers(clone.headers);headers.set("Cache-Control","public, max-age=60");await cache.put(key,new Response(clone.body,{status:clone.status,headers}));}
    catch(error){console.warn("Finanx market-feed cache write skipped.",String(error?.message||error));}
  }
  return response;
}
async function watchlist(req,env){
  const user=await authUser(req,env);if(!user)return json({error:"Sign in to use your watchlist."},401);
  const body=await req.json().catch(()=>({})),action=String(body.action||"list");
  let items=[];
  if(user.auth_store==="kv"){
    if(!env.AUTH_KV)return json({error:"Watchlist storage is temporarily unavailable."},503);
    const key="watchlist:"+user.id;
    items=await env.AUTH_KV.get(key,"json")||[];
    if(action==="add"){
      const ticker=String(body.ticker||"").trim().toUpperCase();if(!validTicker(ticker))return json({error:"Enter a valid ticker."},400);
      if(!items.some(item=>item.ticker===ticker)){
        if(items.length>=100)return json({error:"Watchlist limit is 100 instruments."},409);
        items.unshift({ticker,created_at:isoNow()});
        await env.AUTH_KV.put(key,JSON.stringify(items));
      }
    }else if(action==="remove"){
      const ticker=String(body.ticker||"").trim().toUpperCase();items=items.filter(item=>item.ticker!==ticker);
      await env.AUTH_KV.put(key,JSON.stringify(items));
    }else if(action!=="list")return json({error:"Unknown watchlist action."},400);
  }else{
    if(action==="add"){
      const ticker=String(body.ticker||"").trim().toUpperCase();if(!validTicker(ticker))return json({error:"Enter a valid ticker."},400);
      const count=await first(env,"SELECT COUNT(*) AS n FROM watchlist_items WHERE user_id=?",user.id);
      const exists=await first(env,"SELECT id FROM watchlist_items WHERE user_id=? AND ticker=?",user.id,ticker);
      if(!exists&&Number(count?.n||0)>=100)return json({error:"Watchlist limit is 100 instruments."},409);
      await run(env,"INSERT OR IGNORE INTO watchlist_items(id,user_id,ticker,created_at) VALUES(?,?,?,?)",crypto.randomUUID(),user.id,ticker,isoNow());
    }else if(action==="remove"){
      const ticker=String(body.ticker||"").trim().toUpperCase();await run(env,"DELETE FROM watchlist_items WHERE user_id=? AND ticker=?",user.id,ticker);
    }else if(action!=="list")return json({error:"Unknown watchlist action."},400);
    items=await all(env,"SELECT ticker,created_at FROM watchlist_items WHERE user_id=? ORDER BY created_at DESC",user.id);
  }
  const output=await Promise.all(items.map(async item=>{
    const fullCutoff=new Date(Date.now()-INDEX_CACHE_HOURS*3600000).toISOString(),previewCutoff=new Date(Date.now()-INDEX_CACHE_HOURS*3600000).toISOString();
    let row=await first(env,"SELECT result,indexed_at,indexer,horizon FROM market_index WHERE ticker=? AND period='10y' AND horizon=60 AND indexer='FullIndex' AND indexed_at>=?",item.ticker,fullCutoff);
    if(!row)row=await first(env,"SELECT result,indexed_at,indexer,horizon FROM market_index WHERE ticker=? AND period='5y' AND horizon=30 AND indexer='PreviewIndex' AND indexed_at>=?",item.ticker,previewCutoff);
    const analysis=parse(row?.result);
    return {...item,indexer:row?.indexer||null,indexed_at:row?.indexed_at||null,analysis:analysis?{company:analysis.company,currency:analysis.currency,price:analysis.price,change_percent:analysis.change_percent,history_preview:analysis.history?.close?.slice(-60)||[],forecast_preview:analysis.forecast?.hybrid||[],forecast_horizon:row.horizon,expected_change_percent:analysis.forecast?.expected_change_percent}:null};
  }));
  return json({items:output});
}
async function requestMarketScan(req,env){
  if(!await rateLimit(env,req,"market-scan",30,3600000))return json({error:"Market Scan refresh limit reached. Try again later."},429);
  // Read PreviewIndex 30-day and FullIndex 60-day records only; never queues new analyses.
  const previewCutoff=new Date(Date.now()-INDEX_CACHE_HOURS*3600000).toISOString(),fullCutoff=new Date(Date.now()-INDEX_CACHE_HOURS*3600000).toISOString();
  const rows=await all(env,"SELECT ticker,period,indexer,horizon,indexed_at,result FROM market_index WHERE ((indexer='PreviewIndex' AND horizon=30 AND indexed_at>=?) OR (indexer='FullIndex' AND horizon=60 AND indexed_at>=?)) ORDER BY indexed_at DESC LIMIT 1000",previewCutoff,fullCutoff);
  const byTicker=new Map();
  for(const row of rows){
    const analysis=parse(row.result), forecast=analysis?.forecast;
    const expected=Number(forecast?.expected_change_percent);
    if(!analysis||!Number.isFinite(expected)||expected<=0)continue;
    const existing=byTicker.get(row.ticker);
    // Prefer PreviewIndex 30-day cards; FullIndex 60-day records are fallback only.
    if(!existing || (row.indexer==="PreviewIndex"&&existing.indexer!=="PreviewIndex") || (row.indexer===existing.indexer&&row.indexed_at>existing.indexed_at)){
      byTicker.set(row.ticker,{ticker:row.ticker,company:analysis.company||row.ticker,currency:analysis.currency||"USD",price:analysis.price??null,change_percent:analysis.change_percent??null,indexer:row.indexer,indexed_at:row.indexed_at,history_preview:analysis.history?.close?.slice(-45)||[],forecast_preview:forecast?.hybrid?.slice(0,row.horizon)||[],forecast_horizon:row.horizon,expected_change_percent:expected,risk_score:analysis.risk?.score??null,source:"Indexed "+row.horizon+"-day forecast"});
    }
  }
  const ranked=[...byTicker.values()].sort((a,b)=>b.expected_change_percent-a.expected_change_percent);
  return json({scan_type:"positive_indexed_preview30_full60_rank",queued:0,total_indexed:rows.length,scanned:ranked.length,items:ranked,generated_at:isoNow(),message:"Positive indexed forecasts: PreviewIndex 30-day and FullIndex 60-day, ranked highest to lowest. No new analysis jobs were queued."});
}
async function listJobs(req,env){
  const user=await authUser(req,env);
  if(user)return json({jobs:await all(env,"SELECT id,ticker,save_to_indexer AS indexer,job_type,status,progress,stage,updated_at FROM analysis_jobs WHERE user_id=? OR job_type='scan' ORDER BY created_at DESC LIMIT 40",user.id)});
  return json({jobs:await all(env,"SELECT id,ticker,save_to_indexer AS indexer,job_type,status,progress,stage,updated_at FROM analysis_jobs WHERE job_type='scan' ORDER BY created_at DESC LIMIT 24")});
}
async function processJob(id,env){
  const job=await first(env,"SELECT * FROM analysis_jobs WHERE id=?",id);
  if(!job||job.status==="completed")return;
  const indexer=job.save_to_indexer==="FullIndex"?"FullIndex":"PreviewIndex",period=indexer==="FullIndex"?"10y":job.period||"5y",cooldownCutoff=new Date(Date.now()-INDEX_CACHE_HOURS*3600000).toISOString();
  const recent=await first(env,"SELECT result,indexed_at,source_job_id FROM market_index WHERE ticker=? AND period=? AND horizon=? AND indexer=? AND indexed_at>=? LIMIT 1",job.ticker,period,job.horizon,indexer,cooldownCutoff);
  if(recent?.result&&job.job_type!=="hard_rescan"){
    await run(env,"UPDATE analysis_jobs SET status='completed',result=?,error=NULL,progress=100,stage='Eight-hour cache active; reused existing index',updated_at=? WHERE id=?",recent.result,isoNow(),id);
    return;
  }
  try{
    await run(env,"UPDATE analysis_jobs SET status='running',attempts=attempts+1,progress=3,stage='Starting analysis worker',updated_at=? WHERE id=?",isoNow(),id);
    const result=await makeAnalysis(env,job),stored=JSON.stringify(result);
    await run(env,"INSERT INTO market_index(ticker,period,horizon,indexer,indexed_at,source_job_id,result) VALUES(?,?,?,?,?,?,?) ON CONFLICT(ticker,period,horizon,indexer) DO UPDATE SET indexed_at=excluded.indexed_at,source_job_id=excluded.source_job_id,result=excluded.result",job.ticker,period,job.horizon,indexer,isoNow(),id,stored);
    await run(env,"INSERT OR IGNORE INTO ticker_catalog(ticker,company,currency,last_indexed_at,created_at) VALUES(?,?,?,?,?)",job.ticker,result.company,result.currency,isoNow(),isoNow());
    await run(env,"UPDATE analysis_jobs SET status='completed',result=?,error=NULL,progress=100,stage='Analysis complete',updated_at=? WHERE id=?",stored,isoNow(),id);
  }catch(error){
    const message=String(error?.message||error||"Analysis failed").slice(0,800);
    await run(env,"UPDATE analysis_jobs SET status='failed',error=?,progress=0,stage='Analysis failed',updated_at=? WHERE id=?",message,isoNow(),id);
    throw error;
  }
}
async function discoverIndexTickers(){
  const screeners=["most_actives","day_gainers","day_losers","undervalued_large_caps","growth_technology_stocks","small_cap_gainers"];
  const found=[];
  await Promise.all(screeners.map(async scrId=>{
    try{
      const url=new URL("https://query1.finance.yahoo.com/v1/finance/screener/predefined/saved");
      url.searchParams.set("scrIds",scrId);url.searchParams.set("count","100");url.searchParams.set("start","0");
      const response=await fetch(url,{headers:{"User-Agent":"Mozilla/5.0 FinanxResearch/1.0","Accept":"application/json"},signal:AbortSignal.timeout(9000)});
      if(!response.ok)return;
      const data=await response.json(),quotes=data?.finance?.result?.[0]?.quotes||[];
      for(const quote of quotes){
        const ticker=String(quote.symbol||"").toUpperCase();
        if(quote.quoteType==="EQUITY"&&validTicker(ticker)&&!ticker.includes("^")&&!ticker.includes("="))found.push(ticker);
      }
    }catch{}
  }));
  return [...new Set(found)];
}
async function refreshIndexes(env,indexer){
  const period=indexer==="FullIndex"?"10y":"5y",horizon=indexer==="FullIndex"?60:30,cutoff=new Date(Date.now()-INDEX_CACHE_HOURS*3600000).toISOString(),staleCutoff=new Date(Date.now()-10*60000).toISOString(),MAX_INDEXED=30000;
  // Recover jobs whose D1 status outlived their queue message (e.g. messages expired or a consumer crashed).
  const stale=await all(env,"SELECT id,ticker FROM analysis_jobs WHERE save_to_indexer=? AND status IN ('queued','running') AND updated_at<? ORDER BY updated_at ASC LIMIT 4",indexer,staleCutoff);
  if(stale.length){
    const queue=indexer==="FullIndex"?env.FULLINDEX_QUEUE:env.PREVIEWINDEX_QUEUE;
    if(!queue?.sendBatch)throw new Error(indexer+" queue binding is unavailable during recovery");
    const batch=stale.map(job=>({body:{jobId:job.id}}));
    await queue.sendBatch(batch);
    await Promise.all(stale.map(job=>run(env,"UPDATE analysis_jobs SET status='queued',progress=0,stage='Recovered stale job; requeued by scheduled scan',updated_at=? WHERE id=?",isoNow(),job.id)));
  }
  const discovered=await discoverIndexTickers();
  const catalog=(await all(env,"SELECT ticker FROM ticker_catalog ORDER BY COALESCE(last_indexed_at,'') ASC LIMIT 500")).map(x=>x.ticker);
  const [recentRows,activeRows,allIndexedRows]=await Promise.all([
    all(env,"SELECT ticker FROM market_index WHERE period=? AND horizon=? AND indexer=? AND indexed_at>=?",period,horizon,indexer,cutoff),
    all(env,"SELECT ticker FROM analysis_jobs WHERE save_to_indexer=? AND status IN ('queued','running')",indexer),
    all(env,"SELECT DISTINCT ticker FROM market_index WHERE indexer=?",indexer)
  ]);
  const recentTickers=new Set(recentRows.map(row=>row.ticker)),activeTickers=new Set(activeRows.map(row=>row.ticker)),indexedTickers=new Set(allIndexedRows.map(row=>row.ticker));
  const candidates=[...new Set([...discovered,...catalog,...POPULAR])],batch=[];
  for(const ticker of candidates){
    if(!validTicker(ticker)||recentTickers.has(ticker)||activeTickers.has(ticker))continue;
    // Existing expired entries can refresh; only new distinct tickers count against the 30,000 cap.
    if(!indexedTickers.has(ticker)&&indexedTickers.size>=MAX_INDEXED)continue;
    const id=crypto.randomUUID(),created=isoNow();
    await run(env,"INSERT INTO analysis_jobs(id,ticker,period,horizon,save_to_indexer,status,created_at,updated_at,stage,progress) VALUES(?,?,?,?,?,'queued',?,?,?,0)",id,ticker,period,horizon,indexer,created,created,"Scheduled "+indexer+" continuous discovery refresh");
    activeTickers.add(ticker);indexedTickers.add(ticker);batch.push({body:{jobId:id}});
    if(batch.length>=4)break;
  }
  if(batch.length){const queue=indexer==="FullIndex"?env.FULLINDEX_QUEUE:env.PREVIEWINDEX_QUEUE;if(!queue?.sendBatch)throw new Error(indexer+" queue binding is unavailable");await queue.sendBatch(batch);}
}
async function modelLearning(url,env){
  const indexer=(url.searchParams.get("indexer")||"PreviewIndex").toLowerCase()==="fullindex"?"FullIndex":"PreviewIndex";
  const prefix=indexer+":";
  const rows=await all(env,"SELECT model_key,observations,correct,accuracy,weight,updated_at FROM model_learning_state WHERE model_key LIKE ? ORDER BY accuracy DESC",prefix+"%");
  return json({indexer,profiles:rows.map(row=>({...row,key:row.model_key.slice(prefix.length)})),profile_count:rows.length,observations:rows.reduce((sum,row)=>sum+Number(row.observations||0),0),updated_at:rows[0]?.updated_at||null});
}
async function queueStatus(req,env){
  const user=await authUser(req,env),cutoff=new Date(Date.now()-7*86400000).toISOString();
  const rows=user
    ? await all(env,"SELECT status,COUNT(*) AS count FROM analysis_jobs WHERE (user_id=? OR job_type='scan') AND created_at>=? GROUP BY status",user.id,cutoff)
    : await all(env,"SELECT status,COUNT(*) AS count FROM analysis_jobs WHERE job_type='scan' AND created_at>=? GROUP BY status",cutoff);
  const counts={queued:0,running:0,completed:0,failed:0};
  for(const row of rows)counts[row.status]=(counts[row.status]||0)+Number(row.count||0);
  return json({counts,active:counts.queued+counts.running,total:Object.values(counts).reduce((a,b)=>a+b,0),updated_at:isoNow()});
}
async function searchRoute(url,env,req){
  const query=url.searchParams.get("q")||url.searchParams.get("query")||"";
  if(!query.trim())return json({suggestions:[]});
  const next=new URL(url.toString());next.pathname="/api/market-feed";next.searchParams.set("q",query);
  return marketFeed(next,env,req);
}
async function handleApi(req,env,url){
  const path=url.pathname;
  if(req.method==="OPTIONS")return new Response(null,{status:204,headers:CORS});
  if(path==="/api/health"){
    try{
      await first(env,"SELECT 1 AS ok");
      const queueReady=typeof env.ANALYSIS_QUEUE?.send==="function",fullIndexQueueReady=typeof env.FULLINDEX_QUEUE?.sendBatch==="function",ok=queueReady&&fullIndexQueueReady;
      return json({ok,service:"revised-finanx",database:"D1",queue:queueReady?"Cloudflare Queues":"Unavailable",full_index_queue:fullIndexQueueReady?"Bound":"Unavailable",time:isoNow()},ok?200:503);
    }catch(error){return json({ok:false,service:"revised-finanx",database:"Unavailable",queue:typeof env.ANALYSIS_QUEUE?.send==="function"?"Cloudflare Queues":"Unavailable",time:isoNow()},503);}
  }
  if(path.startsWith("/api/auth/"))return authRoute(req,env,url);
  if(path==="/api/market-feed"&&req.method==="GET")return cachedMarketFeed(url,env,req);
  if(path==="/api/news"&&req.method==="GET")return newsRoute(url,env,req);
  if(path==="/api/news-article"&&req.method==="GET")return newsArticleRoute(url,env,req);
  if(path==="/api/indexed-stats"&&req.method==="GET")return indexedStats(env);
  if(path==="/api/search"&&req.method==="GET")return searchRoute(url,env,req);
  if(path==="/api/model-learning"&&req.method==="GET")return modelLearning(url,env);
  if(path==="/api/queue-status"&&req.method==="GET")return queueStatus(req,env);
  if(path==="/api/watchlist"&&req.method==="POST")return watchlist(req,env);
  if(path==="/api/market-scan"&&req.method==="POST")return requestMarketScan(req,env);
  if(path==="/api/jobs"&&req.method==="GET")return listJobs(req,env);
  if(path==="/api/request-analysis"&&req.method==="POST")return requestAnalysis(req,env);
  if(path==="/api/analysis-status"&&req.method==="GET")return analysisStatus(req,url,env);
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
    return new Response(PAGE,{headers:{"Content-Type":"text/html; charset=utf-8","Cache-Control":"no-store","X-Content-Type-Options":"nosniff","Referrer-Policy":"strict-origin-when-cross-origin","X-Frame-Options":"DENY","Permissions-Policy":"camera=(), microphone=(), geolocation=()","Content-Security-Policy":"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self' https://revised-finanx.stock-analyser-2026.workers.dev; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"}});
  },
  async queue(batch,env){
    for(const message of batch.messages){
      try{const id=message.body?.jobId;if(!id)throw new Error("Queue message has no jobId");await processJob(id,env);message.ack();}
      catch(error){
        console.error("Queue job failed",error);
        const id=message.body?.jobId,attempts=Number(message.attempts||1);
        if(id&&attempts<5){
          await run(env,"UPDATE analysis_jobs SET status='queued',progress=0,stage='Retrying after a temporary worker error',error=?,updated_at=? WHERE id=?",String(error?.message||error).slice(0,800),isoNow(),id);
          message.retry({delaySeconds:Math.min(300,20*Math.max(1,attempts))});
        }else{
          if(id)await run(env,"UPDATE analysis_jobs SET status='failed',progress=0,stage='Retry limit reached',error=?,updated_at=? WHERE id=?",String(error?.message||error).slice(0,800),isoNow(),id);
          message.ack();
        }
      }
    }
  },
  async scheduled(controller,env,ctx){
    const cron=controller.cron||"";
    if(cron==="*/5 * * * *"){
      // Continuously discover and queue eligible stocks; each index type has its own 30,000 cap.
      ctx.waitUntil(refreshIndexes(env,"PreviewIndex").catch(error=>console.error("PreviewIndex scheduled refresh failed",error)));
      ctx.waitUntil(refreshIndexes(env,"FullIndex").catch(error=>console.error("FullIndex scheduled refresh failed",error)));
      const scheduledAt=new Date(Number(controller.scheduledTime||Date.now()));
      // The PreviewIndex cron also runs at Sunday 00:00 UTC; do housekeeping there
      // instead of adding another cron trigger and another scheduled invocation.
      if(scheduledAt.getUTCDay()===0&&scheduledAt.getUTCHours()===0){
        ctx.waitUntil(run(env,"DELETE FROM sessions WHERE expires_at<?",isoNow()));
        ctx.waitUntil(run(env,"DELETE FROM analysis_jobs WHERE status IN ('completed','failed') AND updated_at<?",new Date(Date.now()-14*86400000).toISOString()));
      }
    }
  }
};
