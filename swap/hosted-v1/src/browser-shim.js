export {Buffer} from 'buffer';
export const process = {env:{},browser:true,nextTick:(fn,...args)=>queueMicrotask(()=>fn(...args)),emitWarning:message=>console.warn(message)};
