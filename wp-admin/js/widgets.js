var wpWidgets;(function(a){wpWidgets={init:function(){var f,d=a("div.widgets-sortables"),c=!!("undefined"!=typeof isRtl&&isRtl),e=(isRtl?"marginRight":"marginLeft"),b;a("#widgets-right").children(".widgets-holder-wrap").children(".sidebar-name").click(function(){var h=a(this).siblings(".widgets-sortables"),g=a(this).parent();if(!g.hasClass("closed")){h.sortable("disable");g.addClass("closed")}else{g.removeClass("closed");h.sortable("enable").sortable("refresh")}});a("#widgets-left").children(".widgets-holder-wrap").children(".sidebar-name").click(function(){a(this).parent().toggleClass("closed")});d.each(function(){if(a(this).parent().hasClass("inactive")){return true}var i=50,g=a(this).children(".widget").length;i=i+parseInt(g*48,10);a(this).css("minHeight",i+"px")});a("a.widget-action").live("click",function(){var i={},j=a(this).closest("div.widget"),g=j.children(".widget-inside"),h=parseInt(j.find("input.widget-width").val(),10);if(g.is(":hidden")){if(h>250&&g.closest("div.widgets-sortables").length){i.width=h+30+"px";if(g.closest("div.widget-liquid-right").length){i[e]=235-h+"px"}j.css(i)}wpWidgets.fixLabels(j);g.slideDown("fast")}else{g.slideUp("fast",function(){j.css({width:"",margin:""})})}return false});a("input.widget-control-save").live("click",function(){wpWidgets.save(a(this).closest("div.widget"),0,1,0);return false});a("a.widget-control-remove").live("click",function(){wpWidgets.save(a(this).closest("div.widget"),1,1,0);return false});a("a.widget-control-close").live("click",function(){wpWidgets.close(a(this).closest("div.widget"));return false});d.children(".widget").each(function(){wpWidgets.appendTitle(this);if(a("p.widget-error",this).length){a("a.widget-action",this).click()}});a("#widget-list").children(".widget").draggable({connectToSortable:"div.widgets-sortables",handle:"> .widget-top > .widget-title",distance:2,helper:"clone",zIndex:5,containment:"document",start:function(h,g){g.helper.find("div.widget-description").hide();b=this.id},stop:function(h,g){if(f){a(f).hide()}f=""}});d.sortable({placeholder:"widget-placeholder",items:"> .widget",handle:"> .widget-top > .widget-title",cursor:"move",distance:2,containment:"document",start:function(h,g){g.item.children(".widget-inside").hide();g.item.css({margin:"",width:""})},stop:function(i,g){if(g.item.hasClass("ui-draggable")&&g.item.data("draggable")){g.item.draggable("destroy")}if(g.item.hasClass("deleting")){wpWidgets.save(g.item,1,0,1);g.item.remove();return}var h=g.item.find("input.add_new").val(),l=g.item.find("input.multi_number").val(),k=g.item.attr("id"),j=a(this).attr("id");g.item.css({margin:"",width:""});if(h){if("multi"==h){g.item.html(g.item.html().replace(/<[^<>]+>/g,function(n){return n.replace(/__i__|%i%/g,l)}));g.item.attr("id",b.replace("__i__",l));b="";l++;a("div#"+k).find("input.multi_number").val(l)}else{if("single"==h){g.item.attr("id","new-"+k);f="div#"+k}}wpWidgets.save(g.item,0,0,1);g.item.find("input.add_new").val("");g.item.find("a.widget-action").click();return}wpWidgets.saveOrder(j)},receive:function(i,h){var g=a(h.sender);if(!a(this).is(":visible")||this.id.indexOf("orphaned_widgets")!=-1){g.sortable("cancel")}if(g.attr("id").indexOf("orphaned_widgets")!=-1&&!g.children(".widget").length){g.parents(".orphan-sidebar").slideUp(400,function(){a(this).remove()})}}}).sortable("option","connectWith","div.widgets-sortables").parent().filter(".closed").children(".widgets-sortables").sortable("disable");a("#available-widgets").droppable({tolerance:"pointer",accept:function(g){return a(g).parent().attr("id")!="widget-list"},drop:function(h,g){g.draggable.addClass("deleting");a("#removing-widget").hide().children("span").html("")},over:function(h,g){g.draggable.addClass("deleting");a("div.widget-placeholder").hide();if(g.draggable.hasClass("ui-sortable-helper")){a("#removing-widget").show().children("span").html(g.draggable.find("div.widget-title").children("h4").html())}},out:function(h,g){g.draggable.removeClass("deleting");a("div.widget-placeholder").show();a("#removing-widget").hide().children("span").html("")}})},saveOrder:function(c){if(c){a("#"+c).closest("div.widgets-holder-wrap").find("img.ajax-feedback").css("visibility","visible")}var b={action:"widgets-order",savewidgets:a("#_wpnonce_widgets").val(),sidebars:[]};a("div.widgets-sortables").each(function(){if(a(this).sortable){b["sidebars["+a(this).attr("id")+"]"]=a(this).sortable("toArray").join(",")}});a.post(ajaxurl,b,function(){a("img.ajax-feedback").css("visibility","hidden")});this.resize()},save:function(g,d,e,b){var h=g.closest("div.widgets-sortables").attr("id"),f=g.find("form").serialize(),c;g=a(g);a(".ajax-feedback",g).css("visibility","visible");c={action:"save-widget",savewidgets:a("#_wpnonce_widgets").val(),sidebar:h};if(d){c.delete_widget=1}f+="&"+a.param(c);a.post(ajaxurl,f,function(i){var j;if(d){if(!a("input.widget_number",g).val()){j=a("input.widget-id",g).val();a("#available-widgets").find("input.widget-id").each(function(){if(a(this).val()==j){a(this).closest("div.widget").show()}})}if(e){b=0;g.slideUp("fast",function(){a(this).remove();wpWidgets.saveOrder()})}else{g.remove();wpWidgets.resize()}}else{a(".ajax-feedback").css("visibility","hidden");if(i&&i.length>2){a("div.widget-content",g).html(i);wpWidgets.appendTitle(g);wpWidgets.fixLabels(g)}}if(b){wpWidgets.saveOrder()}})},appendTitle:function(b){var c=a('input[id*="-title"]',b);if(c=c.val()){c=c.replace(/<[^<>]+>/g,"").replace(/</g,"&lt;").replace(/>/g,"&gt;");a(b).children(".widget-top").children(".widget-title").children().children(".in-widget-title").html(": "+c)}},resize:function(){a("div.widgets-sortables").each(function(){if(a(this).parent().hasClass("inactive")){return true}var c=50,b=a(this).children(".widget").length;c=c+parseInt(b*48,10);a(this).css("minHeight",c+"px")})},fixLabels:function(b){b.children(".widget-inside").find("label").each(function(){var c=a(this).attr("for");if(c&&c==a("input",this).attr("id")){a(this).removeAttr("for")}})},close:function(b){b.children(".widget-inside").slideUp("fast",function(){b.css({width:"",margin:""})})}};a(document).ready(function(b){wpWidgets.init()})})(jQuery);