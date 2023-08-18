
-- Import redis client
require('hiredis')

-- Import md5 for simple/fast hashing
md5 = require('md5')

-- Import JSON processing library
json = require('cjson')

-- Make connection to redis
redis_con = hiredis.connect("127.0.0.1", 6379)

---- This is the magic ----
-- In short the use a list with overall TTL an populate event times we then prune
-- in a controlled manor allowing a build up to reach our boiling point trigger
function get_stat_count(name, value, list_inspect_count, timeout)
    -- INPUT --
    -- name = overall key that contains value markers to track - IE: ip
    -- value = the value tracked for - IE 1.1.1.1
    -- list_inspect_count = The number of items to inspect for removal from the list
    --                      when new items are added. This creates how fast or slow
    --                      the score will raise. This is critical to sync with
    --                      a timeout
    -- timeout = The length in seconds to keep a value in count

    -- OUTPUT --
    -- count = The current count AKA score of key:value 

    if (timeout == nil or timeout == 0) then
            return(0)
    end

    -- Hash items to keep store a little safer at rest and to unify keys
    local hit_key = 'stat_count:' .. md5.sumhexa(name) .. ':' .. md5.sumhexa(value)

    -- Get the last x oldest items
    -- This does 2 things:
    --   * Limit resource need and speeds things up
    --   * Adds the ability to control the raise and fall rate of scoring
    local db_list = redis_con:command('LRANGE', hit_key, 0, list_inspect_count)
    
    -- Run item list and remove expired items in single Redis exec. 
    redis_con:command('MULTI')
            if (db_list ~= nil) then
                    for i = 1, #db_list do
                            hittime = db_list[i]
                            if (tonumber(hittime) + tonumber(timeout) <= os.time()) then
                                    redis_con:command('LREM', hit_key, 0, hittime)
                            end
                    end
            end
            redis_con:command('RPUSH', hit_key, os.time())
            redis_con:command('EXPIRE', hit_key, timeout)
            redis_con:command('EXEC')

    -- Pull current list count to get score
    local count = redis_con:command('LLEN', hit_key)
    return(count)
end

-- I generally use fuzzy hashes so I can match small changes but a simple hash
-- can work too providing a certain amount of logic is put into the data hashed
-- to ensure you're matching as close to a 1:1 with what you're identifing as unique
function create_fingerprint(data)
    return(md5.sumhexa(json.encode(data)))
end

-- Merges values
function merge_items(table1, table2)
    for k,v in pairs(table2) do
        if type(v) == "table" then
            if type(table1[k] or false) == "table" then
                merge_items(table1[k] or {}, table2[k] or {})
            else
                table1[k] = v
            end
        else
            tabe1[k] = v
        end
    end
    return(table1)
end

function do_block(value)
    -- Some logic to block value
    return(true)
end

-- Some header sanity scrubbing
function sanitize_headers(headers)
    -- Items with values generally not unique to an application
    local scrub_list = {'remote_agent'}

    -- Items to remove altogether IE time, cookies etc)
    local remove_list = {'cookies'}

    for i = 1, #scrub_list do
        headers[scrub_list[i]] = ''
    end

    for i = 1, #remove_list do
        headers[remove_list[i]] = nil
    end

    return(headers)
end

-- Utility functtion to check a value exists in table
function in_table(list, x)
    for _, v in pairs(list) do
        if (v == x) then return true end
    end
    return false
end


------ END BP Setup ------

-- Example use case -- 
-- Identify how many time a certain web software from the same IP has hit a certain
-- path with a particular action. IE simple flood, scrape, or brute force detection
score_timeout = 5 -- Remove items older than 5 seconds
score_inspect_count = 20 -- Inspect the last 20 items for removable. 
score_trigger_count = 200 -- In this use case we're triggering on only a high score. 
                           -- Some use cases benefit from a range (IE determining a 
                           -- flow range tolorance)

-- Get processing values - This here for example. These values should change quite often
-- in the wild.
ip_address = '1.1.1.1'
web_path = '/example/path/file.html'
headers = {
    remote_agent = 'Mozilla Fake Gecko 42.38934398',
    language = 'en-us',
    accept = 'application/json',
    nasty_code_payload = 'do_jerky_stuff()'
}

-- Empty as this is rally just to show an idea
bad_fingerprints = {}

-- Scoring weighting values (used to score items of higher value over others)
score = {
    ip_fp = 1,
    path_fp = 2
}

-- Remove some key values generally faked keeping order unique factors
santitized_client_headers = sanitize_headers(headers) 

-- For params generally only the keys are important as the values often are purely 
-- attack payload and is valueable mostly post block
json_params = {} -- say the data is submitted as a JSON request
post_params = {} -- the data is from POST parameters
query_params = {} -- the data is from query parameters

fp_data = {}
fp_data['headers'] = santitized_client_headers

-- Merge data methods
raw_params = {}
raw_params = merge_items(raw_params, json_params)
raw_params = merge_items(raw_params, post_params)
raw_params = merge_items(raw_params, query_params)

-- Note generally I don't keep must value data as it's the keys that generally depicts action
fp_data['params'] = {}
for k, v in pairs(raw_params) do
    table.insert(fp_data['params'], k)
end

-- Create simple fingerprint
fp = create_fingerprint(fp_data)


-- Once you have a fingerprint you can use it like an any other IOC to create a block list with.
if (in_table(bad_fingerprints, fp)) then
   do_block(ip_address)
end

-- Score IP w/ FP and multiply by weight
ip_fp_score = get_stat_count(
    'fingerprint_ip', -- The name we give the stat
    fp .. '_' .. md5.sumhexa(ip_address), -- geneate value from fp, ip, and path
    score_inspect_count, -- Score removal inspect count
    score_timeout -- Score removal timeout
) * score['ip_fp']

-- Score IP w/ FP
path_fp_score = get_stat_count(
    'fingerprint_path', -- The name we give the stat
    fp .. '_' .. md5.sumhexa(ip_address), -- geneate value from fp and path
    score_inspect_count, -- Score removal inspect count
    score_timeout -- Score removal timeout
) * score['path_fp']

-- Combine scores to give an overall value to evaluate trigger
score = ip_fp_score + path_fp_score

print ("Score: ", score)

-- Check score is over or equal to threshhold and block IP
if ( score >=  score_trigger_count) then
    do_block(ip_address)
end
