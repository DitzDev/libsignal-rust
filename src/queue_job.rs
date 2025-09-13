use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::Mutex;

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

lazy_static::lazy_static! {
    static ref QUEUE_ASYNC_BUCKETS: Arc<Mutex<HashMap<String, Vec<BoxFuture<()>>>>> = 
        Arc::new(Mutex::new(HashMap::new()));
}

const GC_LIMIT: usize = 10000;

async fn async_queue_executor(bucket: String) {
    let offset = 0;
    
    loop {
        let mut buckets = QUEUE_ASYNC_BUCKETS.lock().await;
        
        if let Some(queue) = buckets.get_mut(&bucket) {
            let limit = std::cmp::min(queue.len(), GC_LIMIT);
            
            if limit == 0 {
                buckets.remove(&bucket);
                break;
            }
            
            let mut tasks_to_run = Vec::new();
            for _ in offset..limit {
                if let Some(task) = queue.pop() {
                    tasks_to_run.push(task);
                }
            }
            
            drop(buckets);
            
            for task in tasks_to_run {
                task.await;
            }
            
            let buckets = QUEUE_ASYNC_BUCKETS.lock().await;
            if let Some(queue) = buckets.get(&bucket) {
                if queue.is_empty() {
                    break;
                }
            }
        } else {
            break;
        }
    }
}

pub async fn queue_job<F, R>(bucket: String, awaitable: F) -> R
where
    F: Future<Output = R> + Send + 'static,
    R: Send + 'static,
{
    let (sender, receiver) = tokio::sync::oneshot::channel();
    
    let wrapped_task = Box::pin(async move {
        let result = awaitable.await;
        let _ = sender.send(result);
    });
    
    let mut buckets = QUEUE_ASYNC_BUCKETS.lock().await;
    let is_inactive = !buckets.contains_key(&bucket);
    
    buckets.entry(bucket.clone()).or_insert_with(Vec::new).push(wrapped_task);
    
    if is_inactive {
        let bucket_clone = bucket.clone();
        tokio::spawn(async_queue_executor(bucket_clone));
    }
    
    drop(buckets);
    
    receiver.await.unwrap()
}