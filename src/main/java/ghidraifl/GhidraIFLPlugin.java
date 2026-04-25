package ghidraifl;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import javax.swing.SwingUtilities;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.KeyBindingData;
import docking.action.MenuData;
import docking.action.ToolBarData;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramEvent;
import resources.Icons;


/**
 * Interactive Functions List plugin - entry point.
 */
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = "IFL",
	category = PluginCategoryNames.NAVIGATION,
	shortDescription = "Interactive Functions List",
	description = "Interactive Functions List (IFL) by hasherezade for Ghidra, port of IDA IFL",
	servicesRequired = { ghidra.app.services.GoToService.class }
)
public class GhidraIFLPlugin extends ProgramPlugin {

	private final IFLProvider provider;
	private DomainObjectListener domainListener;
	private boolean refreshPending = false;

	public GhidraIFLPlugin(PluginTool tool) {
		super(tool);

		// Create provider; the framework will register it
		provider = new IFLProvider(tool, getName());

		//createActions();			// disabled, Window → Interactive Functions List (IFL)
		createToolbarActions();  	// refresh + Ctrl+F 

	    domainListener = new DomainObjectListener() {
	        @Override
	        public void domainObjectChanged(DomainObjectChangedEvent ev) {

	  		  	// Skip if the user turned off live update
	        	if (!provider.isLiveUpdateEnabled()) {
	        		return;
	        	}
	        	
	        	// Only trigger on function-level / symbol changes
	            if (!ev.contains(ProgramEvent.FUNCTION_ADDED,
	                             ProgramEvent.FUNCTION_REMOVED,
	                             ProgramEvent.FUNCTION_CHANGED,
	                             ProgramEvent.SYMBOL_ADDED,
	                             ProgramEvent.SYMBOL_REMOVED,
	                             ProgramEvent.SYMBOL_RENAMED)) {
	                return;
	            }
	            scheduleRefresh();
	        }
	    };
	}
	
	private void createActions() {
		DockingAction openAction =
			new DockingAction("Interactive Functions List", getName()) {
				@Override
				public void actionPerformed(ActionContext context) {
					provider.setProgram(getCurrentProgram());
					getTool().showComponentProvider(provider, true);
				}
			};

		openAction.setMenuBarData(new MenuData(
			new String[] { "Window", "Interactive Functions List (IFL)" }, null, "IFL"));

		tool.addAction(openAction);
	}

	@Override
	protected void programActivated(Program program) {
	    super.programActivated(program);
	    if (program != null && domainListener != null) {
	        program.addListener(domainListener);
	    }
	    provider.setProgram(program);
	}
	
	@Override
	protected void programDeactivated(Program program) {
	    super.programDeactivated(program);
	    if (program != null && domainListener != null) {
	        program.removeListener(domainListener);
	    }
	    provider.setProgram(null);
	}
	
	@Override
	protected void programClosed(Program program) {
	    super.programClosed(program);
	    if (program != null && domainListener != null) {
	        program.removeListener(domainListener);
	    }
	}
	
	private void createToolbarActions() {

	    // Refresh IFL view
	    DockingAction refreshAction = new DockingAction("Refresh IFL", getName()) {
	        @Override
	        public void actionPerformed(ActionContext context) {
	            provider.refresh();
	        }

	        @Override
	        public boolean isEnabledForContext(ActionContext context) {
	            return getCurrentProgram() != null;
	        }
	    };
	    refreshAction.setToolBarData(new ToolBarData(Icons.REFRESH_ICON, null)); // use standard Refresh Icon
	    tool.addLocalAction(provider, refreshAction);
	    
	    // Ctrl+F: focus search field in IFL
	    DockingAction focusSearchAction = new DockingAction("Focus IFL Search", getName()) {
	        @Override
	        public void actionPerformed(ActionContext context) {
	            provider.focusSearchField();
	        }

	        @Override
	        public boolean isEnabledForContext(ActionContext context) {
	            // Only when provider is the active one
	            return context.getComponentProvider() == provider;
	        }
	    };
	    focusSearchAction.setKeyBindingData(
	        new KeyBindingData(KeyEvent.VK_F, InputEvent.CTRL_DOWN_MASK));

	    tool.addLocalAction(provider, focusSearchAction);
	}
	
	private void scheduleRefresh() {
	    if (refreshPending || provider == null) {
	        return;
	    }
	    refreshPending = true;
	    SwingUtilities.invokeLater(() -> {
	        refreshPending = false;
	        Program prog = getCurrentProgram();
	        if (prog != null) {
	            provider.refresh();
	        }
	        else {
	            provider.setProgram(null);
	        }
	    });
	}
}