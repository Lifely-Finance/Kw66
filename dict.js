/* ============================================================
   KW66 Morse Messenger — словарь для авто-коррекции (T9-подобной)

   Отдельный файл, не файл сообщений: это статический список слов,
   зашитый в приложение, а не пользовательские данные — поэтому его
   можно спокойно кэшировать service worker'ом наравне с кодом.

   Списки намеренно компактные (несколько сотен самых частых слов
   на каждый язык) — цель не покрыть весь язык, а поймать типичные
   опечатки в коротких сообщениях. Расширяется дозаписью в массивы
   ниже, без изменения логики.
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

// Точные сокращения — раскрываются только при полном совпадении токена
// целиком (без нечёткого поиска), поэтому безопасны и предсказуемы.
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
  if(m===0) return n; if(n===0) return m;
  let prev=new Array(n+1); for(let j=0;j<=n;j++) prev[j]=j;
  for(let i=1;i<=m;i++){
    const cur=[i];
    for(let j=1;j<=n;j++){
      const cost=a[i-1]===b[j-1]?0:1;
      cur[j]=Math.min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost);
    }
    prev=cur;
  }
  return prev[n];
}

function isCyrillic(s){ return /[А-ЯЁ]/.test(s); }
function isLatin(s){ return /[A-Z]/.test(s); }

// Ищет ближайшее словарное слово для токена. Возвращает исходный
// токен без изменений, если точное совпадение уже есть, если в
// токене остался нераспознанный символ (□), или если ближайший
// кандидат слишком далёк, чтобы предлагать его вслепую.
function correctToken(token){
  if(!token) return token;
  const hasBox=token.includes("□");
  if(hasBox) return token; // нечего чинить словарём — есть нераспознанный Морзе-символ
  let words, abbr;
  if(isCyrillic(token)){ words=RU_WORDS; abbr=RU_ABBR; }
  else if(isLatin(token)){ words=EN_WORDS; abbr=EN_ABBR; }
  else return token; // цифры/пунктуация — не трогаем
  if(abbr[token]) return abbr[token];
  if(words.includes(token)) return token; // уже валидное слово
  const maxDist=token.length<=4?1:2;
  let best=null,bestDist=Infinity;
  for(const w of words){
    if(Math.abs(w.length-token.length)>maxDist) continue;
    const d=levenshtein(token,w);
    if(d<bestDist){ bestDist=d; best=w; }
  }
  return (best && bestDist<=maxDist) ? best : token;
}

// Прогоняет коррекцию по каждому слову сообщения, сохраняя пробелы
// как есть (split/map/join не схлопывает двойные пробелы).
function correctMessage(text){
  if(!text) return text;
  return text.split(" ").map(correctToken).join(" ");
}

global.KW66Dict={ correctToken, correctMessage, EN_WORDS, RU_WORDS, EN_ABBR, RU_ABBR, levenshtein };
})(window);
