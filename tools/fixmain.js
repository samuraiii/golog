const fs = require('fs');
function patch(file, edits) {
  let s = fs.readFileSync(file, 'utf8');
  for (const [from, to, count] of edits) {
    if (typeof from === 'string') {
      if (!s.includes(from)) { console.log('MISS ' + file + ' :: ' + JSON.stringify(from).slice(0, 90)); continue; }
      const n = s.split(from).length - 1;
      s = s.split(from).join(to);
      console.log('ok   ' + file + ' x' + n + ' :: ' + JSON.stringify(from).slice(0, 70));
    } else {
      const m = s.match(from);
      if (!m) { console.log('MISS ' + file + ' :: /' + from.source + '/'); continue; }
      s = s.replace(from, to);
      console.log('ok   ' + file + ' :: /' + from.source.slice(0, 60) + '/');
    }
  }
  fs.writeFileSync(file, s);
}

/* Server.Thumbnail is a bool field; the -x/-g plumbing used two spellings.
   One field: ThumbnailsEnabled (the config key stays "Use thumbs"). */
patch('internal/elog/server.go', [
  ['\tThumbnail   bool // generate thumbnails with convert(1)',
   '\tThumbnailsEnabled bool // -g / "Use thumbs": make thumbnails with convert(1)', 1],
  ['s.Thumbnail = s.Config.GetFlag(g, "Use thumbs")', 's.ThumbnailsEnabled = s.Config.GetFlag(g, "Use thumbs")', 2],
]);
patch('internal/elog/attachments.go', [
  [/s\.Thumbnail\b(?!Path|s)/g, 's.ThumbnailsEnabled', null],
  [/func \(s \*Server\) Thumbnail\(/g, 'func (s *Server) ThumbnailCompat(', null],
]);
patch('internal/elog/summary.go', [
  [/s\.Thumbnail\b(?!Path|s)/g, 's.ThumbnailsEnabled', null],
]);
patch('cmd/elogd/main.go', [
  ['s.Thumbnail = o.thumbs || cfg.GetFlag(elog.ConfigScope{Group: "global"}, "Thumbnail")',
   's.ThumbnailsEnabled = o.thumbs', 1],
  ['s.UseThumbs = s.Thumbnail || cfg.GetFlag(elog.ConfigScope{Group: "global"}, "UseThumbs")',
   's.ThumbnailsEnabled = s.ThumbnailsEnabled || cfg.GetFlag(elog.ConfigScope{Group: "global"}, "Use thumbs")', 1],
  ['orAny(s.Addr, "*"), s.Port, o.configFile, len(s.Order), s.BasePath, s.Exec, s.Thumbnail)',
   'orAny(s.Addr, "*"), s.Port, o.configFile, len(s.Order), s.BasePath, s.Exec, s.ThumbnailsEnabled)', 1],
]);

/* Config is a field of *Server, not a method. */
patch('internal/elog/request.go', [
  ['r.Server().Config()', 'r.Server().Config', 1],
]);
patch('internal/elog/submit.go', [
  ['q.Server().Config()', 'q.Server().Config', 1],
]);
