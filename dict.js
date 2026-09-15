/* ============================================================
   KW66 Morse Messenger — словарь для авто-коррекции
   ============================================================ */
(function(global){
"use strict";
const EN_WORDS=["A","I","AM","AN","AND","ARE","AS","AT","BE","BEEN","BUT","BY","CAN","COULD",
"DAY","DID","DO","DOES","DONE","DON'T","FOR","FROM","GET","GO","GOING","GOOD","GOT","HAD","HAS",
"HAVE","HE","HELLO","HER","HERE","HEY","HI","HIM","HIS","HOME","HOW","HOPE","I'LL","I'M","IF","IN",
"INTO","IS","IT","ITS","JUST","KNOW","LATER","LET","LIKE","LOVE","ME","MEET","MINE","MORE","MUST",
"MY","NEED","NEVER","NEW","NO","NOT","NOW","OF","OK","OKAY","ON","ONE","OR","OUR","OUT","OVER",
"PLEASE","REALLY","SEE","SHE","SO","SOME","SOON","SORRY","STILL","TAKE","TELL","THANK","THANKS",
"THAT","THE","THEIR","THEM","THEN","THERE","THESE","THEY","THIS","THOSE","TIME","TO","TODAY",
"TOMORROW","TONIGHT","TOO","US","WAIT","WANT","WAS","WE","WELL","WENT","WERE","WHAT","WHEN",
"WHERE","WHICH","WHO","WHY","WILL","WITH","WORK","WOULD","YES","YOU","YOUR","YOU'RE","MORNING",
"NIGHT","WEEK","MONTH","YEAR","CALL","TEXT","BACK","SOON","LOVE","MISS","MISS YOU","FINE","GREAT",
"HAPPY","SAD","TIRED","BUSY","FREE","READY","SURE","MAYBE","AGAIN","ALSO","ALWAYS","ANYTHING",
"ANYWAY","AROUND","AWAY","BEFORE","BETWEEN","BOTH","CANNOT","COME","DOWN","EACH","EVEN","EVERY",
"FAR","FEEL","FEW","FIND","FIRST","GIVE","HELP","HOUSE","HOW'S","KEEP","KIND","LAST","LEAVE",
"LEFT","LESS","LIFE","LITTLE","LONG","LOOK","MAKE","MANY","MEAN","MOST","MUCH","NAME","NEAR",
"NEXT","NOTHING","ONLY","OTHER","OWN","PART","PLACE","PUT","RIGHT","SAME","SAY","SEEM","SINCE",
"SOMETHING","START","SUCH","TAKE","THAN","THANK YOU","THING","THINK","THOUGH","THROUGH","TOGETHER",
"TOO","TRY","TURN","UNDER","UP","USE","VERY","WAY","WEEK","WHILE","WORD","WORLD","YOUR"];
const RU_WORDS=["А","АГА","АЛЛО","БУДУ","БУДЕТ","БЫЛ","БЫЛА","БЫЛО","БЫТЬ","В","ВЕЧЕР","ВЕЧЕРОМ",
"ВЗЯТЬ","ВИЖУ","ВОТ","ВРЕМЯ","ВСЕ","ВСЁ","ВСЕГДА","ВЧЕРА","ВЫ","ГДЕ","ГОВОРИ","ГОД","ДА","ДАВАЙ",
"ДАЖЕ","ДАТЬ","ДЕЛА","ДЕЛАТЬ","ДЕНЬ","ДЛЯ","ДО","ДОБРО","ДОМ","ДОМА","ДРУГ","ДУМАЮ","ЕГО","ЕЕ",
"ЕЁ","ЕЙ","ЕМУ","ЕСЛИ","ЕСТЬ","ЕЩЕ","ЕЩЁ","ЖДУ","ЖИЗНЬ","ЗА","ЗАВТРА","ЗАЧЕМ","ЗДЕСЬ",
"ЗДОРОВО","ЗНАЮ","И","ИДИ","ИДУ","ИЗ","ИЛИ","ИМЕТЬ","К","КАЖДЫЙ","КАК","КОГДА","КОНЕЧНО",
"КТО","КУДА","ЛЮБЛЮ","МЕНЯ","МЕСТО","МНЕ","МНОГО","МОГУ","МОЖЕТ","МОЖНО","МОЙ","МОЯ","МЫ",
"НА","НАДО","НАМ","НАС","НАША","НАШ","НЕ","НЕТ","НИЧЕГО","НО","НОВЫЙ","НОЧЬ","НУ","О","ОДИН",
"ОКОЛО","ОН","ОНА","ОНИ","ОПЯТЬ","ОТ","ОЧЕНЬ","ПЕРВЫЙ","ПЛОХО","ПО","ПОГОДИ","ПОЖАЛУЙСТА",
"ПОКА","ПОСЛЕ","ПОТОМ","ПОЧЕМУ","ПРИВЕТ","ПРО","РАБОТА","РАД","РАДА","РАЗ","С","САМ","САМА",
"СВОЙ","СЕБЯ","СЕГОДНЯ","СЕЙЧАС","СКОРО","СЛУШАЙ","СМОТРИ","СНОВА","СПАСИБО","СПИ","СПОКОЙНОЙ",
"ТАК","ТАКЖЕ","ТАМ","ТВОЙ","ТЕБЕ","ТЕБЯ","ТЕПЕРЬ","ТО","ТОГДА","ТОЖЕ","ТОЛЬКО","ТУТ","ТЫ","У",
"УЖЕ","УТРО","УТРОМ","ХОРОШО","ХОЧУ","ХОЧЕШЬ","ЧАС","ЧТО","ЧТОБЫ","ЭТО","ЭТОТ","Я","ЛЮБЛЮ",
"СКУЧАЮ","ЗВОНИ","НАПИШИ","ЖДУ","ГОТОВ","ГОТОВА","НАДЕЮСЬ","КОНЧЕНО","ПОНЯЛ","ПОНЯЛА","ХОРОШИЙ",
"ПЛОХОЙ","БОЛЬШОЙ","МАЛЕНЬКИЙ","НОВОСТИ","ДЕЛО","ВОПРОС","ОТВЕТ","ПРАВДА","НЕПРАВДА"];
const EN_ABBR={
"U":"YOU","R":"ARE","UR":"YOUR","THX":"THANKS","TY":"THANK YOU","PLS":"PLEASE","PLZ":"PLEASE",
"BTW":"BY THE WAY","OMW":"ON MY WAY","ASAP":"AS SOON AS POSSIBLE","IDK":"I DO NOT KNOW",
"IMO":"IN MY OPINION","LMK":"LET ME KNOW","BRB":"BE RIGHT BACK","NP":"NO PROBLEM",
"YW":"YOU ARE WELCOME","GM":"GOOD MORNING","GN":"GOOD NIGHT","LOL":"LOL"
};
const RU_ABBR={
"СПС":"СПАСИБО","ПЖЛ":"ПОЖАЛУЙСТА","ПЖ":"ПОЖАЛУЙСТА","ЩАС":"СЕЙЧАС","СЙЧ":"СЕЙЧАС",
"ЗВ":"ЗВОНИ","НАП":"НАПИШИ","ДР":"ДОБРОЕ УТРО","СН":"СПОКОЙНОЙ НОЧИ"
};
function levenshtein(a,b){
 const m=a.length,n=b.length;
 if(m===0)return n;if(n===0)return m;
 let prev=Array.from({length:n+1},(_,j)=>j);
 for(let i=1;i<=m;i++){
  const cur=[i];
  for(let j=1;j<=n;j++){
   const cost=a[i-1]===b[j-1]?0:1;
   cur[j]=Math.min(prev[j]+1,cur[j-1]+1,prev[j-1]+cost);
  }
  prev=cur;
 }
 return prev[n];
}
function isCyrillic(s){return /[А-ЯЁ]/.test(s);}
function isLatin(s){return /[A-Z]/.test(s);}
function getDict(token){
 if(isCyrillic(token))return {words:RU_WORDS,abbr:RU_ABBR};
 if(isLatin(token))return {words:EN_WORDS,abbr:EN_ABBR};
 return null;
}
function correctToken(token){
 if(!token)return token;
 if(token.includes("□"))return token;
 const d=getDict(token);
 if(!d)return token;
 if(d.abbr[token])return d.abbr[token];
 if(d.words.includes(token))return token;
 const maxDist=token.length<=4?1:2;
 let best=null,bestDist=Infinity;
 for(const w of d.words){
  if(Math.abs(w.length-token.length)>maxDist)continue;
  const dist=levenshtein(token,w);
  if(dist<bestDist){bestDist=dist;best=w;}
 }
 return(best&&bestDist<=maxDist)?best:token;
}

/* Strong word-boundary correction.
   It considers both the user's existing spaces and a version with them removed,
   then searches for a high-confidence segmentation into dictionary words.
   It never changes a boundary merely because a fuzzy candidate happens to exist. */
function normalizeText(text){
 if(!text)return text;
 text=text.trim().replace(/\s+/g," ");
 const raw=text.split(" ");
 if(raw.length===1 && raw[0].length<2)return text;

 const language=isCyrillic(text)?"ru":isLatin(text)?"en":null;
 if(!language)return text;
 const words=language==="ru"?RU_WORDS:EN_WORDS;
 const wordSet=new Set(words);
 const abbr=language==="ru"?RU_ABBR:EN_ABBR;

 function exactSegment(s){
  const n=s.length;
  const dp=Array(n+1).fill(null);
  dp[0]=[];
  for(let i=0;i<n;i++){
   if(!dp[i])continue;
   for(let j=i+1;j<=n;j++){
    const w=s.slice(i,j);
    if(wordSet.has(w)){
     const candidate=[...dp[i],w];
     if(!dp[j] || candidate.length<dp[j].length)dp[j]=candidate;
    }
   }
  }
  return dp[n];
 }

 const joined=raw.join("");
 const joinedSeg=exactSegment(joined);

 // If removing all spaces gives a clean dictionary segmentation,
 // prefer it only when the user's current tokenization is clearly worse.
 if(joinedSeg && joinedSeg.length>=2){
  const currentExact=raw.filter(Boolean).every(w=>wordSet.has(w)||abbr[w]);
  if(!currentExact)return joinedSeg.join(" ");
 }

 // For each adjacent boundary, test removing it. Only accept if the merged
 // token is an exact dictionary word; this handles ПРИВ Е ТДРУГ after the
 // second stage below without guessing from Levenshtein alone.
 let out=raw.slice();
 for(let i=0;i<out.length-1;){
  const merged=out[i]+out[i+1];
  if(wordSet.has(merged)){
   out.splice(i,2,merged);
   i=Math.max(0,i-1);
  }else i++;
 }

 // Correct individual tokens only after boundary normalization.
 out=out.map(correctToken);
 return out.join(" ");
}

function correctMessage(text){
 if(!text)return text;
 const normalized=normalizeText(text);
 return normalized;
}
global.KW66Dict={
 correctToken,correctMessage,normalizeText,
 EN_WORDS,RU_WORDS,EN_ABBR,RU_ABBR,levenshtein
};
})(window);
