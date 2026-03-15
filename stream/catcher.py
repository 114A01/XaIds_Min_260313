
Start() //外部程式呼叫，開始捕獲封包的流程

_capture_loop() //擷取風包的迴圈
_on_package()   //當擷取到封包時呼叫

extract_features()  //將擷取到的封包轉換成可儲存的特徵資料
_put_to_queue() //將轉換後的特徵資料放入佇列
