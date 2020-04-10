import debug from "debug";
import {DUMP_SESSION_KEYS} from './constants';


let keyLogger;
if(DUMP_SESSION_KEYS){
    keyLogger = debug('libp2p:session')
}
else{
    keyLogger = () => {}
}

export const sessionKeyLogger = keyLogger;
export const logger = debug('libp2p:noise');