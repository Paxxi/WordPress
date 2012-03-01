(function(d,e,f){var a=e.event,c;a.special.smartresize={setup:function(){e(this).bind("resize",a.special.smartresize.handler)},teardown:function(){e(this).unbind("resize",a.special.smartresize.handler)},handler:function(j,g){var i=this,h=arguments;j.type="smartresize";if(c){clearTimeout(c)}c=setTimeout(function(){jQuery.event.handle.apply(i,h)},g==="execAsap"?0:100)}};e.fn.smartresize=function(g){return g?this.bind("smartresize",g):this.trigger("smartresize",["execAsap"])};e.Mason=function(g,h){this.element=e(h);this._create(g);this._init()};e.Mason.settings={isResizable:true,isAnimated:false,animationOptions:{queue:false,duration:500},gutterWidth:0,isRTL:false,isFitWidth:false,containerStyle:{position:"relative"}};e.Mason.prototype={_filterFindBricks:function(h){var g=this.options.itemSelector;return !g?h:h.filter(g).add(h.find(g))},_getBricks:function(h){var g=this._filterFindBricks(h).css({position:"absolute"}).addClass("masonry-brick");return g},_create:function(i){this.options=e.extend(true,{},e.Mason.settings,i);this.styleQueue=[];var h=this.element[0].style;this.originalStyle={height:h.height||""};var j=this.options.containerStyle;for(var k in j){this.originalStyle[k]=h[k]||""}this.element.css(j);this.horizontalDirection=this.options.isRTL?"right":"left";this.offset={x:parseInt(this.element.css("padding-"+this.horizontalDirection),10),y:parseInt(this.element.css("padding-top"),10)};this.isFluid=this.options.columnWidth&&typeof this.options.columnWidth==="function";var g=this;setTimeout(function(){g.element.addClass("masonry")},0);if(this.options.isResizable){e(d).bind("smartresize.masonry",function(){g.resize()})}this.reloadItems()},_init:function(g){this._getColumns();this._reLayout(g)},option:function(g,h){if(e.isPlainObject(g)){this.options=e.extend(true,this.options,g)}},layout:function(o,p){for(var m=0,n=o.length;m<n;m++){this._placeBrick(o[m])}var g={};g.height=Math.max.apply(Math,this.colYs);if(this.options.isFitWidth){var k=0,m=this.cols;while(--m){if(this.colYs[m]!==0){break}k++}g.width=(this.cols-k)*this.columnWidth-this.options.gutterWidth}this.styleQueue.push({$el:this.element,style:g});var h=!this.isLaidOut?"css":(this.options.isAnimated?"animate":"css"),j=this.options.animationOptions;var l;for(m=0,n=this.styleQueue.length;m<n;m++){l=this.styleQueue[m];l.$el[h](l.style,j)}this.styleQueue=[];if(p){p.call(o)}this.isLaidOut=true},_getColumns:function(){var g=this.options.isFitWidth?this.element.parent():this.element,h=g.width();this.columnWidth=this.isFluid?this.options.columnWidth(h):this.options.columnWidth||this.$bricks.outerWidth(true)||h;this.columnWidth+=this.options.gutterWidth;this.cols=Math.floor((h+this.options.gutterWidth)/this.columnWidth);this.cols=Math.max(this.cols,1)},_placeBrick:function(p){var n=e(p),r,v,k,t,l;r=Math.ceil(n.outerWidth(true)/(this.columnWidth+this.options.gutterWidth));r=Math.min(r,this.cols);if(r===1){k=this.colYs}else{v=this.cols+1-r;k=[];for(l=0;l<v;l++){t=this.colYs.slice(l,l+r);k[l]=Math.max.apply(Math,t)}}var g=Math.min.apply(Math,k),u=0;for(var m=0,q=k.length;m<q;m++){if(k[m]===g){u=m;break}}var o={top:g+this.offset.y};o[this.horizontalDirection]=this.columnWidth*u+this.offset.x;this.styleQueue.push({$el:n,style:o});var s=g+n.outerHeight(true),h=this.cols+1-q;for(m=0;m<h;m++){this.colYs[u+m]=s}},resize:function(){var g=this.cols;this._getColumns();if(this.isFluid||this.cols!==g){this._reLayout()}},_reLayout:function(h){var g=this.cols;this.colYs=[];while(g--){this.colYs.push(0)}this.layout(this.$bricks,h)},reloadItems:function(){this.$bricks=this._getBricks(this.element.children())},reload:function(g){this.reloadItems();this._init(g)},appended:function(h,i,j){if(i){this._filterFindBricks(h).css({top:this.element.height()});var g=this;setTimeout(function(){g._appended(h,j)},1)}else{this._appended(h,j)}},_appended:function(g,i){var h=this._getBricks(g);this.$bricks=this.$bricks.add(h);this.layout(h,i)},remove:function(g){this.$bricks=this.$bricks.not(g);g.remove()},destroy:function(){this.$bricks.removeClass("masonry-brick").each(function(){this.style.position="";this.style.top="";this.style.left=""});var g=this.element[0].style;for(var h in this.originalStyle){g[h]=this.originalStyle[h]}this.element.unbind(".masonry").removeClass("masonry").removeData("masonry");e(d).unbind(".masonry")}};
/*!
   * jQuery imagesLoaded plugin v1.1.0
   * http://github.com/desandro/imagesloaded
   *
   * MIT License. by Paul Irish et al.
   */
e.fn.imagesLoaded=function(n){var l=this,j=l.find("img").add(l.filter("img")),g=j.length,m="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==",i=[];function k(){n.call(l,j)}function h(o){if(o.target.src!==m&&e.inArray(this,i)===-1){i.push(this);if(--g<=0){setTimeout(k);j.unbind(".imagesLoaded",h)}}}if(!g){k()}j.bind("load.imagesLoaded error.imagesLoaded",h).each(function(){var o=this.src;this.src=m;this.src=o});return l};var b=function(g){if(this.console){console.error(g)}};e.fn.masonry=function(h){if(typeof h==="string"){var g=Array.prototype.slice.call(arguments,1);this.each(function(){var i=e.data(this,"masonry");if(!i){b("cannot call methods on masonry prior to initialization; attempted to call method '"+h+"'");return}if(!e.isFunction(i[h])||h.charAt(0)==="_"){b("no such method '"+h+"' for masonry instance");return}i[h].apply(i,g)})}else{this.each(function(){var i=e.data(this,"masonry");if(i){i.option(h||{});i._init()}else{e.data(this,"masonry",new e.Mason(h,this))}})}return this}})(window,jQuery);