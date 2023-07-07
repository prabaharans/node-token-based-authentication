/**
 * Configurations of logger.
 */
const winston = require('winston');
const winstonRotator = require('winston-daily-rotate-file');

const consoleConfig = [
  new winston.transports.Console({
    'colorize': true
  })
];

const createLogger = winston.createLogger({
  'transports': consoleConfig,
  exitOnError: false, // do not exit on handled exceptions
});

let ts = Date.now();

let date_time = new Date(ts);
let date = ("0" + date_time.getDate()).slice(-2);
let month = ("0" + (date_time.getMonth() + 1)).slice(-2);
let year = date_time.getFullYear();
let hours = date_time.getHours();
let minutes = date_time.getMinutes();
let seconds = date_time.getSeconds();
const successLogger = createLogger;
successLogger.add(new winston.transports.File({
  'name': 'access-file',
  'level': 'info',
  'filename': './logs/'+year + "/" + month + "/" + date + "/" + hours + "/" + minutes + "/" + seconds+'/access.log',
  // 'json': false,
  // 'datePattern': 'yyyy-MM-dd-h-i-s',
  // 'prepend': true
}));

const errorLogger = createLogger;
errorLogger.add(new winston.transports.File({
  'name': 'error-file',
  'level': 'error',
  'filename': './logs/'+year + "/" + month + "/" + date + "/" + hours + "/" + minutes + "/" + seconds+'/error.log',
  // 'json': false,
  // 'datePattern': 'yyyy-MM-dd--h-i-s',
  // 'prepend': true
}));

module.exports = {
  'successlog': successLogger,
  'errorlog': errorLogger
};
