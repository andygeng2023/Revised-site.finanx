const clamp = (n, lo, hi) => Math.max(lo, Math.min(hi, Number.isFinite(n) ? n : 0));
const mean = a => a.length ? a.reduce((s,x)=>s+x,0)/a.length : 0;
const median = a => { if(!a.length)return 0;const x=[...a].sort((p,q)=>p-q);return x[Math.floor(x.length/2)]; };
const variance = a => { const m=mean(a);return mean(a.map(x=>(x-m)**2)); };
const stdev = a => Math.sqrt(variance(a));
const ema = (values,period) => {
  if(!values.length)return 0;
  const alpha=2/(period+1);let value=values[0];
  for(let i=1;i<values.length;i++)value=alpha*values[i]+(1-alpha)*value;
  return value;
};
const slope = values => {
  const n=values.length;if(n<3)return 0;let sx=0,sy=0,sxx=0,sxy=0;
  values.forEach((v,i)=>{sx+=i;sy+=v;sxx+=i*i;sxy+=i*v;});
  const den=n*sxx-sx*sx;return den?(n*sxy-sx*sy)/den:0;
};
const rsi = values => {
  if(values.length<3)return 50;
  const d=[];for(let i=1;i<values.length;i++)d.push(values[i]-values[i-1]);
  const gains=d.filter(x=>x>0),losses=d.filter(x=>x<0).map(Math.abs);
  const avgGain=mean(gains),avgLoss=mean(losses);
  if(avgLoss===0)return avgGain===0?50:100;
  const rs=avgGain/avgLoss;return 100-(100/(1+rs));
};
const sma = (values,n)=>mean(values.slice(-n));
const ret=(a,b)=>b>0?Math.log(a/b):0;

export const FULL_MODELS = [
  {key:"last-drift",name:"Last-Value Drift"},
  {key:"sma-drift",name:"Simple Moving Average Drift"},
  {key:"ema-trend",name:"Exponential Moving Average Trend"},
  {key:"linear-regression",name:"Log Linear Regression"},
  {key:"autoregression",name:"Autoregressive Model"},
  {key:"arima-difference",name:"ARIMA Difference Approximation"},
  {key:"momentum-20",name:"20-Day Momentum"},
  {key:"mean-reversion",name:"Mean Reversion"},
  {key:"rsi-reversion",name:"RSI Reversion"},
  {key:"macd-trend",name:"MACD Trend"},
  {key:"bollinger-reversion",name:"Bollinger Reversion"},
  {key:"vol-adjusted-trend",name:"Volatility-Adjusted Trend"},
  {key:"regime-trend",name:"Market Regime Trend"},
  {key:"holt-trend",name:"Holt Trend"},
  {key:"volume-weighted",name:"Volume-Weighted Trend"}
];
export const PREVIEW_KEYS = ["last-drift","sma-drift","ema-trend","linear-regression","autoregression","arima-difference","momentum-20"];
export const HYBRID_GROUPS = [
  ["last-drift","sma-drift","ema-trend"],
  ["linear-regression","autoregression","arima-difference"],
  ["momentum-20","mean-reversion","rsi-reversion"],
  ["macd-trend","bollinger-reversion","vol-adjusted-trend"],
  ["regime-trend","holt-trend","volume-weighted"],
  ["last-drift","linear-regression","momentum-20","regime-trend"],
  ["sma-drift","arima-difference","mean-reversion","holt-trend"],
  ["ema-trend","autoregression","rsi-reversion","volume-weighted"],
  ["linear-regression","macd-trend","vol-adjusted-trend","regime-trend"],
  ["last-drift","sma-drift","ema-trend","holt-trend","volume-weighted"]
];
export const META_GROUPS = [
  ["hybrid-01","hybrid-02","hybrid-04","hybrid-06"],
  ["hybrid-03","hybrid-05","hybrid-07","hybrid-08"],
  ["hybrid-06","hybrid-08","hybrid-09","hybrid-10"]
];
export const MODEL_LABELS = Object.fromEntries([
  ...FULL_MODELS.map(x=>[x.key,x.name]),
  ...HYBRID_GROUPS.map((_,i)=>["hybrid-"+String(i+1).padStart(2,"0"),"Hybrid "+String(i+1).padStart(2,"0")]),
  ...META_GROUPS.map((_,i)=>["meta-"+String(i+1).padStart(2,"0"),"Meta-Hybrid "+String(i+1).padStart(2,"0")]),
  ["primary","Adaptive Primary Hybrid"]
]);

export function getOriginalPredictions(closes,volumes=[]){
  const n=closes.length;
  if(n<45)throw new Error("At least 45 valid closes are required for model analysis.");
  const logReturns=[];
  for(let i=1;i<n;i++)logReturns.push(Math.log(closes[i]/closes[i-1]));
  const last=closes[n-1],r5=mean(logReturns.slice(-5)),r20=mean(logReturns.slice(-20)),r60=mean(logReturns.slice(-60));
  const vol=stdev(logReturns.slice(-60))||0.012;
  const recent=closes.slice(-30),recentSma=sma(closes,20),longSma=sma(closes,60);
  const currentRsi=rsi(closes.slice(-15));
  const e12=ema(closes.slice(-80),12),e26=ema(closes.slice(-100),26);
  const macd=(e12-e26)/(last||1);
  const logPrices=closes.slice(-60).map(Math.log);
  const regression=slope(logPrices);
  const short=closes.slice(-9).map((v,i)=>({v,r:logReturns.at(-9+i)??0}));
  const recentVolume=volumes.slice(-20).filter(x=>x>0);
  const avgVolume=mean(recentVolume)||1;
  const weightedReturn=short.reduce((s,x)=>s+x.r*(1+(volumes.at(-1)||avgVolume)/avgVolume),0)/(short.length||1);
  const recentMean=mean(logReturns.slice(-15));
  const olderMean=mean(logReturns.slice(-45,-15));
  const recentMax=Math.max(...recent),recentMin=Math.min(...recent);
  const maDeviation=last/(recentSma||last)-1;
  const bandWidth=(stdev(recent)||0.01)*2;
  const bandPosition=bandWidth?maDeviation/bandWidth:0;
  const trend=ema(closes.slice(-80),12)/Math.max(1,ema(closes.slice(-100),26))-1;
  const holt=slope(closes.slice(-25).map(Math.log));
  const regime=last>longSma?1:last<longSma?-1:0;
  const predictions={
    "last-drift":clamp(r20*0.82,-0.025,0.025),
    "sma-drift":clamp((sma(closes,5)/(sma(closes,20)||last)-1)*0.5,-0.025,0.025),
    "ema-trend":clamp(trend*0.45,-0.025,0.025),
    "linear-regression":clamp(regression,-0.025,0.025),
    "autoregression":clamp(r5*0.45+(recentMean-olderMean)*0.24,-0.025,0.025),
    "arima-difference":clamp((recentMean-olderMean)*0.42+r20*0.12,-0.025,0.025),
    "momentum-20":clamp(r20*0.68,-0.025,0.025),
    "mean-reversion":clamp(-maDeviation*0.28,-0.025,0.025),
    "rsi-reversion":clamp(((50-currentRsi)/50)*vol*0.28,-0.025,0.025),
    "macd-trend":clamp(macd*0.42,-0.025,0.025),
    "bollinger-reversion":clamp(-bandPosition*0.0015,-0.025,0.025),
    "vol-adjusted-trend":clamp(r60/(1+vol*24),-0.025,0.025),
    "regime-trend":clamp(regime*Math.abs(r60)*0.65+r20*0.15,-0.025,0.025),
    "holt-trend":clamp(holt/last,-0.025,0.025),
    "volume-weighted":clamp(weightedReturn*0.55,-0.025,0.025)
  };
  const drawdown=last/Math.max(...closes.slice(-252))-1;
  return {predictions,diagnostics:{volatility:vol,rsi:currentRsi,macd,drawdown,recentSma,longSma,regime}};
}
function weightFor(globalWeights,key){
  const w=Number(globalWeights?.[key]?.weight);
  return clamp(Number.isFinite(w)?w:1,0.55,1.65);
}
function weightedPrediction(keys,predictions,globalWeights){
  let sum=0,weight=0;
  for(const key of keys){const w=weightFor(globalWeights,key);sum+=(predictions[key]||0)*w;weight+=w;}
  return weight?sum/weight:0;
}
export function ensemblePredictions(original,globalWeights={},full=true){
  const predictions={...original};
  for(let i=0;i<HYBRID_GROUPS.length;i++){
    const key="hybrid-"+String(i+1).padStart(2,"0");
    predictions[key]=weightedPrediction(HYBRID_GROUPS[i],original,globalWeights);
  }
  for(let i=0;i<META_GROUPS.length;i++){
    const key="meta-"+String(i+1).padStart(2,"0");
    predictions[key]=weightedPrediction(META_GROUPS[i],predictions,globalWeights);
  }
  predictions.primary=weightedPrediction(["meta-01","meta-02","meta-03"],predictions,globalWeights);
  if(!full){
    for(const model of FULL_MODELS)if(!PREVIEW_KEYS.includes(model.key))delete predictions[model.key];
  }
  return predictions;
}
export function buildModelEvaluation(closes,volumes=[],globalWeights={},full=true){
  const start=Math.max(90,closes.length-130),stats={};
  for(const model of FULL_MODELS)stats[model.key]={observations:0,correct:0,absolute_error:0};
  for(let i=0;i<HYBRID_GROUPS.length;i++)stats["hybrid-"+String(i+1).padStart(2,"0")]={observations:0,correct:0,absolute_error:0};
  for(let i=0;i<META_GROUPS.length;i++)stats["meta-"+String(i+1).padStart(2,"0")]={observations:0,correct:0,absolute_error:0};
  stats.primary={observations:0,correct:0,absolute_error:0};
  for(let i=start;i<closes.length;i++){
    const train=closes.slice(0,i),trainVolumes=volumes.slice(0,i);
    if(train.length<60||closes[i]<=0||closes[i-1]<=0)continue;
    const base=getOriginalPredictions(train,trainVolumes);
    const predictions=ensemblePredictions(base.predictions,globalWeights,full);
    const actual=Math.log(closes[i]/closes[i-1]);
    for(const [key,prediction] of Object.entries(predictions)){
      if(!stats[key])continue;
      const row=stats[key];row.observations++;
      if(Math.abs(actual)>0.00012&&Math.sign(prediction)===Math.sign(actual))row.correct++;
      row.absolute_error+=Math.abs(prediction-actual);
    }
  }
  for(const row of Object.values(stats)){
    row.accuracy=row.observations?row.correct/row.observations:0.5;
    row.mae=row.observations?row.absolute_error/row.observations:null;
  }
  return {stats,windows:stats.primary.observations,modelKeys:Object.keys(stats)};
}
export function modelCandidates(predictions,stats,globalWeights){
  return Object.entries(predictions).map(([key,signal])=>{
    const metric=stats[key]||{observations:0,accuracy:0.5,mae:null};
    const global=globalWeights[key]||{observations:0,accuracy:0.5,weight:1};
    const type=key==="primary"?"Primary hybrid":key.startsWith("meta-")?"Meta-hybrid":key.startsWith("hybrid-")?"Hybrid":"Original";
    const weight=clamp(Number(global.weight||1)*(0.75+metric.accuracy*0.5),0.4,2.0);
    return {key,name:MODEL_LABELS[key]||key,type,signal:Number(signal),validation_accuracy:Number(metric.accuracy||0.5),mae:metric.mae,observations:Number(global.observations||0)+Number(metric.observations||0),weight};
  });
}
